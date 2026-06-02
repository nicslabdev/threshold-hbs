package es.uma.nicslab.hbs.protocol;

import es.uma.nicslab.hbs.model.CRV;
import org.junit.jupiter.api.Test;

import java.io.IOException;

import static org.junit.jupiter.api.Assertions.*;

class SerializerTest {

    // -------------------------------------------------------------------------
    // CRVSerializer
    // -------------------------------------------------------------------------

    @Test
    void crv_serialize_deserialize_es_identico() throws IOException {
        CRV original = crv();
        byte[] blob = CRVSerializer.serialize(original);
        CRV recuperado = CRVSerializer.deserialize(blob);

        assertArrayEquals(original.getR(),    recuperado.getR());
        assertArrayEquals(original.getCHK(),  recuperado.getCHK());
        assertArrayEquals(original.getPATH(), recuperado.getPATH());

        byte[][][] skOrig = original.getSK();
        byte[][][] skRec  = recuperado.getSK();
        assertEquals(skOrig.length, skRec.length);
        for (int i = 0; i < skOrig.length; i++) {
            assertEquals(skOrig[i].length, skRec[i].length);
            for (int j = 0; j < skOrig[i].length; j++) {
                assertArrayEquals(skOrig[i][j], skRec[i][j]);
            }
        }
    }

    @Test
    void crv_serializado_es_binario_no_vacio() throws IOException {
        byte[] blob = CRVSerializer.serialize(crv());
        assertNotNull(blob);
        assertTrue(blob.length > 0);
    }

    // -------------------------------------------------------------------------
    // CLSerializer
    // -------------------------------------------------------------------------

    @Test
    void cl_serialize_deserialize_es_identico() throws IOException {
        CoalitionEntry[] original = cl();
        byte[] blob = CLSerializer.serialize(original);
        CoalitionEntry[] recuperado = CLSerializer.deserialize(blob);

        assertEquals(original.length, recuperado.length);
        for (int i = 0; i < original.length; i++) {
            assertArrayEquals(original[i].trustees(), recuperado[i].trustees());
            assertEquals(original[i].crvCid(),        recuperado[i].crvCid());
        }
    }

    @Test
    void cl_entrada_unica_correcta() throws IOException {
        CoalitionEntry[] cl = new CoalitionEntry[]{
                new CoalitionEntry(new int[]{0, 1, 2}, "a".repeat(64))
        };
        CoalitionEntry[] rec = CLSerializer.deserialize(CLSerializer.serialize(cl));
        assertArrayEquals(new int[]{0, 1, 2}, rec[0].trustees());
        assertEquals("a".repeat(64), rec[0].crvCid());
    }

    // -------------------------------------------------------------------------
    // Auxiliares
    // -------------------------------------------------------------------------

    private static CRV crv() {
        int n      = 32;
        int chains = 4;
        int steps  = 4;

        byte[] R    = fill(n, 0x01);
        byte[] CHK  = fill(n * 3, 0x02);
        byte[] PATH = fill(n * 5, 0x03);

        byte[][][] sk = new byte[chains][steps][];
        for (int i = 0; i < chains; i++) {
            for (int j = 0; j < steps; j++) {
                sk[i][j] = fill(n, (byte)(i * steps + j));
            }
        }
        return new CRV(R, CHK, PATH, sk);
    }

    private static CoalitionEntry[] cl() {
        return new CoalitionEntry[]{
                new CoalitionEntry(new int[]{0, 1, 2}, "a".repeat(64)),
                new CoalitionEntry(new int[]{0, 1, 3}, "b".repeat(64)),
                new CoalitionEntry(new int[]{1, 2, 3}, "c".repeat(64)),
        };
    }

    private static byte[] fill(int len, int val) {
        byte[] b = new byte[len];
        java.util.Arrays.fill(b, (byte) val);
        return b;
    }
}