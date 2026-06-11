package es.uma.nicslab.hbs.protocol;

import es.uma.nicslab.hbs.lms.*;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.nio.file.Path;

import static org.junit.jupiter.api.Assertions.*;

class BulletinBoardTest {

    @TempDir
    Path tempDir;

    private static final String CL_CID = "a".repeat(64);
    private static final int LENGTH_CHK = 128;
    private static final int LENGTH_PATH = 160;

    private static LMSPublicKeyParameters buildPublicKey(){
        LMSParameters params = new LMSParameters(
                LMSigParameters.lms_sha256_n32_h5,
                LMOtsParameters.sha256_n32_w4);
        java.security.SecureRandom rng = new java.security.SecureRandom();
        LMSKeyGenerationParameters genParams = new LMSKeyGenerationParameters(params, rng);
        LMSKeyPairGenerator gen = new LMSKeyPairGenerator();
        gen.init(genParams);
        return (LMSPublicKeyParameters) gen.generateKeyPair().getPublic();
    }

    @Test
    void save_y_load_preservan_clcid() throws Exception {
        Path file = tempDir.resolve("board.json");
        new BulletinBoard(buildPublicKey(), CL_CID, LENGTH_CHK, LENGTH_PATH).saveTo(file);
        assertEquals(CL_CID, BulletinBoard.loadFrom(file).getClCid());
    }

    @Test
    void save_y_load_preservan_lms_public_key() throws Exception {
        LMSPublicKeyParameters pub = buildPublicKey();
        Path file = tempDir.resolve("board.json");
        new BulletinBoard(pub, CL_CID, LENGTH_CHK, LENGTH_PATH).saveTo(file);
        assertArrayEquals(pub.getEncoded(), BulletinBoard.loadFrom(file).getLmsPublicKey().getEncoded());
    }

    @Test
    void save_y_load_preservan_lengthCHK() throws Exception {
        Path file = tempDir.resolve("board.json");
        new BulletinBoard(buildPublicKey(), CL_CID, LENGTH_CHK, LENGTH_PATH).saveTo(file);
        assertEquals(LENGTH_CHK, BulletinBoard.loadFrom(file).getLengthCHK());
    }

    @Test
    void save_y_load_preservan_lengthPATH() throws Exception {
        Path file = tempDir.resolve("board.json");
        new BulletinBoard(buildPublicKey(), CL_CID, LENGTH_CHK, LENGTH_PATH).saveTo(file);
        assertEquals(LENGTH_PATH, BulletinBoard.loadFrom(file).getLengthPATH());
    }

    @Test
    void fichero_json_contiene_todos_los_campos() throws Exception {
        Path file = tempDir.resolve("board.json");
        new BulletinBoard(buildPublicKey(), CL_CID, LENGTH_CHK, LENGTH_PATH).saveTo(file);
        String json = java.nio.file.Files.readString(file);
        assertTrue(json.contains("lmsPublicKey"));
        assertTrue(json.contains("clCid"));
        assertTrue(json.contains("lengthCHK"));
        assertTrue(json.contains("lengthPATH"));
        assertTrue(json.contains(CL_CID));
        assertTrue(json.contains(String.valueOf(LENGTH_CHK)));
        assertTrue(json.contains(String.valueOf(LENGTH_PATH)));
    }

    @Test
    void exists_false_si_no_existe() {
        assertFalse(BulletinBoard.exists(tempDir.resolve("no-existe.json")));
    }

    @Test
    void exists_true_tras_save() throws Exception {
        Path file = tempDir.resolve("board.json");
        new BulletinBoard(buildPublicKey(), CL_CID, LENGTH_CHK, LENGTH_PATH).saveTo(file);
        assertTrue(BulletinBoard.exists(file));
    }

    @Test
    void save_sobreescribe_board_anterior() throws Exception {
        LMSPublicKeyParameters pub = buildPublicKey();
        Path file = tempDir.resolve("board.json");
        new BulletinBoard(pub, "e".repeat(64), 64,  80).saveTo(file);
        new BulletinBoard(pub, "f".repeat(64), 128, 160).saveTo(file);
        BulletinBoard loaded = BulletinBoard.loadFrom(file);
        assertEquals("f".repeat(64), loaded.getClCid());
        assertEquals(128, loaded.getLengthCHK());
        assertEquals(160, loaded.getLengthPATH());
    }

    @Test
    void valores_del_board_permiten_reconstruir_parametros_del_trustee() throws Exception {
        LMSPublicKeyParameters pub = buildPublicKey();
        Path file = tempDir.resolve("board.json");
        new BulletinBoard(pub, CL_CID, LENGTH_CHK, LENGTH_PATH).saveTo(file);
        BulletinBoard loaded = BulletinBoard.loadFrom(file);
        assertNotNull(loaded.getLmsPublicKey().getOtsParameters());
        assertNotNull(loaded.getLmsPublicKey().getI());
        assertEquals(pub.getOtsParameters().getType(), loaded.getLmsPublicKey().getOtsParameters().getType());
        assertArrayEquals(pub.getI(), loaded.getLmsPublicKey().getI());
    }

}