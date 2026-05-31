package es.uma.nicslab.hbs.trustee;

import es.uma.nicslab.hbs.lms.LMOtsParameters;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.io.IOException;
import java.nio.file.Path;

import static org.junit.jupiter.api.Assertions.*;

class TrusteeConfigTest {

    @TempDir
    Path tempDir;

    private static final byte[] K        = new byte[32];
    private static final int    TYPE     = LMOtsParameters.sha256_n32_w4.getType();
    private static final byte[] I        = new byte[16];
    private static final int    CHK      = 128;
    private static final int    PATH     = 160;
    private static final String CAS_URL  = "http://cas:8080";
    private static final String CL_CID   = "a".repeat(64);

    static {
        for (int i = 0; i < 32; i++) K[i] = (byte) i;
        for (int i = 0; i < 16; i++) I[i] = (byte) (i + 1);
    }

    // -------------------------------------------------------------------------
    // saveTo / loadFrom
    // -------------------------------------------------------------------------

    @Test
    void save_y_load_son_identicos() throws IOException {
        TrusteeConfig original = new TrusteeConfig(K, TYPE, I, CHK, PATH, CAS_URL, CL_CID);

        Path file = tempDir.resolve("trustee-config.bin");
        original.saveTo(file);

        TrusteeConfig loaded = TrusteeConfig.loadFrom(file);

        assertArrayEquals(K, loaded.getK());
        assertEquals(TYPE, loaded.getLmotsParamType());
        assertArrayEquals(I, loaded.getI());
        assertEquals(CHK, loaded.getLengthCHK());
        assertEquals(PATH, loaded.getLengthPath());
        assertEquals(CAS_URL, loaded.getCasUrl());
        assertEquals(CL_CID, loaded.getClCid());
    }

    @Test
    void getLmotsParameters_reconstruye_correctamente() throws IOException {
        TrusteeConfig config = new TrusteeConfig(K, TYPE, I, CHK, PATH, CAS_URL, CL_CID);

        Path file = tempDir.resolve("trustee-config.bin");
        config.saveTo(file);
        TrusteeConfig loaded = TrusteeConfig.loadFrom(file);

        LMOtsParameters params = loaded.getLmotsParameters();
        assertNotNull(params);
        assertEquals(TYPE, params.getType());
    }

    // -------------------------------------------------------------------------
    // exists()
    // -------------------------------------------------------------------------

    @Test
    void exists_false_si_no_se_ha_guardado() {
        Path file = tempDir.resolve("no-existe.bin");
        assertFalse(TrusteeConfig.exists(file));
    }

    @Test
    void exists_true_tras_save() throws IOException {
        TrusteeConfig config = new TrusteeConfig(K, TYPE, I, CHK, PATH, CAS_URL, CL_CID);
        Path file = tempDir.resolve("trustee-config.bin");
        config.saveTo(file);
        assertTrue(TrusteeConfig.exists(file));
    }

    // -------------------------------------------------------------------------
    // Escritura atómica
    // -------------------------------------------------------------------------

    @Test
    void save_sobreescribe_config_anterior() throws IOException {
        Path file = tempDir.resolve("trustee-config.bin");

        TrusteeConfig first = new TrusteeConfig(K, TYPE, I, CHK, PATH, "http://cas-old:8080", CL_CID);
        first.saveTo(file);

        TrusteeConfig second = new TrusteeConfig(K, TYPE, I, CHK, PATH, "http://cas-new:8080", CL_CID);
        second.saveTo(file);

        TrusteeConfig loaded = TrusteeConfig.loadFrom(file);
        assertEquals("http://cas-new:8080", loaded.getCasUrl());
    }

    // -------------------------------------------------------------------------
    // Getters no devuelven referencia interna
    // -------------------------------------------------------------------------

    @Test
    void getK_devuelve_copia() {
        TrusteeConfig config = new TrusteeConfig(K, TYPE, I, CHK, PATH, CAS_URL, CL_CID);
        byte[] k1 = config.getK();
        byte[] k2 = config.getK();
        assertNotSame(k1, k2);
        assertArrayEquals(k1, k2);
    }
}