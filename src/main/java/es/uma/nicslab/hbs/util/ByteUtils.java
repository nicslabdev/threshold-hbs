package es.uma.nicslab.hbs.util;

public class ByteUtils {

    public static byte[] intToBytes(int v) {
        return new byte[]{
                (byte)(v >> 24), (byte)(v >> 16), (byte)(v >> 8), (byte) v
        };
    }

    public static int bytesToInt(byte[] v) {
        if (v == null || v.length != 4)
            throw new IllegalArgumentException("bytesToInt: se esperan exactamente 4 bytes, recibidos: " + (v == null ? "null" : v.length));
        return ((v[0] & 0xFF) << 24)
                | ((v[1] & 0xFF) << 16)
                | ((v[2] & 0xFF) << 8)
                |  (v[3] & 0xFF);
    }

    public static byte[] concat(byte[]... parts) {
        int total = 0;
        for (byte[] p : parts) total += p.length;
        byte[] result = new byte[total];
        int pos = 0;
        for (byte[] p : parts) {
            System.arraycopy(p, 0, result, pos, p.length);
            pos += p.length;
        }
        return result;
    }

    public static byte[] xorBytes(byte[] a, byte[] b) {
        if (a.length != b.length)
            throw new IllegalArgumentException(
                    "xorBytes: longitudes distintas (" + a.length + " vs " + b.length + ")"
            );
        byte[] result = new byte[a.length];
        for (int i = 0; i < a.length; i++) {
            result[i] = (byte) (a[i] ^ b[i]);
        }
        return result;
    }

    public static byte[] xorAll(byte[] original, byte[][] shares) {
        byte[] result = original.clone();
        for (int i = 0; i < shares.length; i++) {
            result = xorBytes(result, shares[i]);
        }
        return result;
    }

    public static byte[][][] xorSK(byte[][][] original, byte[][][][] sharesSK) {
        int chains = original.length;
        int steps  = original[0].length;
        byte[][][] result = new byte[chains][steps][];

        for (int i = 0; i < chains; i++) {
            for (int j = 0; j < steps; j++) {
                result[i][j] = original[i][j].clone();
                for (int t = 0; t < sharesSK.length; t++) {
                    result[i][j] = xorBytes(result[i][j], sharesSK[t][i][j]);
                }
            }
        }
        return result;
    }

    public static boolean constantTimeEquals(byte[] a, byte[] b) {
        if (a.length != b.length) return false;
        int diff = 0;
        for (int i = 0; i < a.length; i++) {
            diff |= (a[i] ^ b[i]);
        }
        return diff == 0;
    }

}
