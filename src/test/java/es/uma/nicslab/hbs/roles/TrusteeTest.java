package es.uma.nicslab.hbs.roles;

import es.uma.nicslab.hbs.lms.*;
import es.uma.nicslab.hbs.model.*;
import es.uma.nicslab.hbs.util.*;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import org.bouncycastle.crypto.AsymmetricCipherKeyPair;

import java.security.SecureRandom;

import static org.junit.jupiter.api.Assertions.*;

public class TrusteeTest {

    private Trustee trustee;
    private TrusteeShare share;
    private byte[] keyIdBytes;
    private byte[] message;
    private byte[] K;
    private int n;
    private int chkLength;
    private int pathLength;
    private LMOtsParameters parameter;
    private byte[] I;

    @BeforeEach
    void setup() throws Exception {

        SecureRandom rng = new SecureRandom();

        // Generar clave PRF del trustee
        K = new byte[32];
        rng.nextBytes(K);

        // Parámetros LMS
        LMSKeyGenerationParameters genParams = new LMSKeyGenerationParameters(
                new LMSParameters(LMSigParameters.lms_sha256_n32_h5, LMOtsParameters.sha256_n32_w4),
                rng
        );
        LMSKeyPairGenerator gen = new LMSKeyPairGenerator();
        gen.init(genParams);
        AsymmetricCipherKeyPair keyPair = gen.generateKeyPair();
        LMSPrivateKeyParameters lmsPrivate = (LMSPrivateKeyParameters) keyPair.getPrivate();

        parameter = lmsPrivate.getOtsParameters();
        I = lmsPrivate.getI();
        n = parameter.getN();
        keyIdBytes = ByteUtils.intToBytes(0);
        chkLength = 2 * n; // k=2 trustees
        pathLength = 5 * n; // h=5 nodos en el árbol Merkle

        share = new TrusteeShare(keyIdBytes, K);
        trustee = new Trustee(parameter, I);
        trustee.loadShare(share);

        message = "mensaje de prueba".getBytes();
    }

    @Test
    void testSign1DevuelveRound1MsgValido() {
        Round1Msg msg = trustee.KK_Sign1(keyIdBytes, message, chkLength);
        assertNotNull(msg, "KK_Sign1 debe devolver Round1Msg");
        assertNotNull(msg.getR_t(), "R_t no debe ser null");
        assertNotNull(msg.getCHK_t(), "CHK_t no debe ser null");
        assertEquals(n, msg.getR_t().length, "R_t debe tener n bytes");
        assertEquals(chkLength, msg.getCHK_t().length, "CHK_t debe tener chkLength bytes");
    }

    @Test
    void testSign1DevuelveNullSiYaHayFirmaEnCurso() {
        trustee.KK_Sign1(keyIdBytes, message, chkLength); // primera llamada — ok
        Round1Msg msg = trustee.KK_Sign1(keyIdBytes, message, chkLength); // segunda — ⊥
        assertNull(msg, "KK_Sign1 debe devolver null si ya hay firma en curso");
    }

    @Test
    void testSign1DevuelveNullSiKeyIdIncorrecto() {
        byte[] wrongKeyId = ByteUtils.intToBytes(99);
        Round1Msg msg = trustee.KK_Sign1(wrongKeyId, message, chkLength);
        assertNull(msg, "KK_Sign1 debe devolver null si el keyId no coincide");
    }

    @Test
    void testSign1EsDeterminista() {
        // Dos trustees con la misma clave y keyId deben producir el mismo R_t y CHK_t
        TrusteeShare share2 = new TrusteeShare(keyIdBytes, K);
        Trustee trustee2 = new Trustee(parameter, I);
        trustee2.loadShare(share2);
        Round1Msg msg1 = trustee.KK_Sign1(keyIdBytes, message, chkLength);
        Round1Msg msg2 = trustee2.KK_Sign1(keyIdBytes, message, chkLength);
        assertArrayEquals(msg1.getR_t(), msg2.getR_t(), "R_t debe ser determinista");
        assertArrayEquals(msg1.getCHK_t(), msg2.getCHK_t(), "CHK_t debe ser determinista");
    }

    @Test
    void testSign2DevuelveNullSinSign1Previo() {
        // Sin llamar a KK_Sign1, current == null → ⊥
        byte[] R = new byte[n];
        new SecureRandom().nextBytes(R);
        byte[] CHK = PRF.evalAUTH(K, keyIdBytes, R, n);
        Round2Msg msg = trustee.KK_Sign2(R, CHK, pathLength);
        assertNull(msg, "KK_Sign2 debe devolver null si no se llamó antes a KK_Sign1");
    }

    @Test
    void testSign2DevuelveNullSiKKAuthFalla() {
        trustee.KK_Sign1(keyIdBytes, message, chkLength);

        // R incorrecto → KK_Auth fallará
        byte[] wrongR = new byte[n];
        new SecureRandom().nextBytes(wrongR);
        byte[] wrongCHK = new byte[n]; // no corresponde a wrongR
        new SecureRandom().nextBytes(wrongCHK);

        Round2Msg msg = trustee.KK_Sign2(wrongR, wrongCHK, pathLength);
        assertNull(msg, "KK_Sign2 debe devolver null si KK_Auth falla");
    }

    @Test
    void testSign2NoReutilizaKeyIdTrasAuthFallida() {
        trustee.KK_Sign1(keyIdBytes, message, chkLength);

        // Auth falla — current se limpia igualmente
        byte[] wrongR   = new byte[n];
        byte[] wrongChk = new byte[n];
        new SecureRandom().nextBytes(wrongR);
        new SecureRandom().nextBytes(wrongChk);
        trustee.KK_Sign2(wrongR, wrongChk, pathLength);

        // Intentar Sign1 de nuevo debe fallar porque current ya se usó
        Round1Msg msg = trustee.KK_Sign1(keyIdBytes, message, chkLength);
        assertNull(msg, "KK_Sign1 no debe poder reutilizarse tras un intento fallido de KK_Sign2");
    }

    @Test
    void testFlujoCompletoRound1Round2() {
        // Round 1
        Round1Msg round1 = trustee.KK_Sign1(keyIdBytes, message, chkLength);
        assertNotNull(round1);

        // Aggregator reconstruye R (simulado: en 1-of-1 R = CRV.R ⊕ R_t)
        byte[] R = round1.getR_t(); // simplificación para el test aislado

        // Aggregator calcula CHK'[t] = PRF^Auth_{K[t]}(KeyID, R)
        byte[] CHK = PRF.evalAUTH(K, keyIdBytes, R, n);

        // Round 2
        Round2Msg round2 = trustee.KK_Sign2(R, CHK, pathLength);

        assertNotNull(round2, "El flujo completo debe producir un Round2Msg válido");
        assertNotNull(round2.getZ_t(), "Z_t no debe ser null");
        assertNotNull(round2.getPATH_t(), "PATH_t no debe ser null");
        assertEquals(parameter.getP() * n, round2.getZ_t().length, "Z_t debe tener p*n bytes");
        assertEquals(pathLength, round2.getPATH_t().length, "PATH_t debe tener pathLength bytes");
    }

    @Test
    void testSign2EsDeterminista() {
        // Dos trustees con la misma clave deben producir el mismo Z_t y PATH_t
        TrusteeShare share2 = new TrusteeShare(keyIdBytes, K);
        Trustee trustee2 = new Trustee(parameter, I);
        trustee2.loadShare(share2);

        byte[] R = new byte[n];
        new SecureRandom().nextBytes(R);
        byte[] CHK = PRF.evalAUTH(K, keyIdBytes, R, n);

        trustee.KK_Sign1(keyIdBytes, message, chkLength);
        trustee2.KK_Sign1(keyIdBytes, message, chkLength);

        Round2Msg msg1 = trustee.KK_Sign2(R, CHK, pathLength);
        Round2Msg msg2 = trustee2.KK_Sign2(R, CHK, pathLength);

        assertArrayEquals(msg1.getZ_t(), msg2.getZ_t(), "Z_t debe ser determinista");
        assertArrayEquals(msg1.getPATH_t(), msg2.getPATH_t(), "PATH_t debe ser determinista");
    }
}