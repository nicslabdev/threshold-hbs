package es.uma.nicslab.hbs.trustee;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.io.IOException;
import java.nio.file.Path;

import static org.junit.jupiter.api.Assertions.*;

class TrusteeConfigTest {

    @TempDir
    Path tempDir;

    private static final byte[] K = new byte[32];

    static {
        for (int i = 0; i < 32; i++) K[i] = (byte) i;
    }

    @Test
    void save_y_load_preservan_K() throws IOException {
        Path file = tempDir.resolve("trustee-config.bin");
        new TrusteeConfig(K).saveTo(file);
        assertArrayEquals(K, TrusteeConfig.loadFrom(file).getK());
    }

    @Test
    void save_y_load_con_K_de_ceros() throws IOException {
        byte[] zeros = new byte[32];
        Path file = tempDir.resolve("trustee-config.bin");
        new TrusteeConfig(zeros).saveTo(file);
        assertArrayEquals(zeros, TrusteeConfig.loadFrom(file).getK());
    }

    @Test
    void save_sobreescribe_config_anterior() throws IOException {
        Path file = tempDir.resolve("trustee-config.bin");
        byte[] k1 = new byte[32];
        byte[] k2 = new byte[32];
        for (int i = 0; i < 32; i++) k1[i] = (byte) i;
        for (int i = 0; i < 32; i++) k2[i] = (byte) (i + 100);
        new TrusteeConfig(k1).saveTo(file);
        new TrusteeConfig(k2).saveTo(file);
        assertArrayEquals(k2, TrusteeConfig.loadFrom(file).getK());
    }

    @Test
    void exists_false_si_no_existe() {
        assertFalse(TrusteeConfig.exists(tempDir.resolve("no-existe.bin")));
    }

    @Test
    void exists_true_tras_save() throws IOException {
        Path file = tempDir.resolve("trustee-config.bin");
        new TrusteeConfig(K).saveTo(file);
        assertTrue(TrusteeConfig.exists(file));
    }

    @Test
    void getK_devuelve_copia() {
        TrusteeConfig config = new TrusteeConfig(K);
        byte[] k1 = config.getK();
        byte[] k2 = config.getK();
        assertNotSame(k1, k2);
        assertArrayEquals(k1, k2);
    }

    @Test
    void modificar_K_original_no_afecta_al_config() {
        byte[] kOriginal = K.clone();
        TrusteeConfig config = new TrusteeConfig(kOriginal);
        kOriginal[0] = (byte) 0xFF;
        assertArrayEquals(K, config.getK());
    }

    @Test
    void loadFrom_lanza_excepcion_si_fichero_no_existe() {
        assertThrows(IOException.class,
                () -> TrusteeConfig.loadFrom(tempDir.resolve("no-existe.bin")));
    }
}