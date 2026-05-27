package es.uma.nicslab.hbs.protocol;

import es.uma.nicslab.hbs.model.CRV;

import java.io.*;

/**
 * Serialización binaria de CRV a byte[] y viceversa.
 *
 * Formato (big-endian, DataOutputStream):
 *
 *   [int]    longitud de R
 *   [bytes]  R
 *   [int]    longitud de CHK
 *   [bytes]  CHK
 *   [int]    longitud de PATH
 *   [bytes]  PATH
 *   [int]    número de cadenas (chains = SK.length)
 *   [int]    número de pasos  (steps  = SK[0].length)
 *   para cada cadena i:
 *     para cada paso j:
 *       [int]    longitud de SK[i][j]
 *       [bytes]  SK[i][j]
 */
public class CRVSerializer {

    private CRVSerializer() {}

    public static byte[] serialize(CRV crv) throws IOException {
        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        DataOutputStream dos = new DataOutputStream(baos);

        writeBytes(dos, crv.getR());
        writeBytes(dos, crv.getCHK());
        writeBytes(dos, crv.getPATH());

        byte[][][] sk = crv.getSK();
        int chains = sk.length;
        int steps  = sk[0].length;
        dos.writeInt(chains);
        dos.writeInt(steps);
        for (int i = 0; i < chains; i++) {
            for (int j = 0; j < steps; j++) {
                writeBytes(dos, sk[i][j]);
            }
        }

        dos.flush();
        return baos.toByteArray();
    }

    public static CRV deserialize(byte[] data) throws IOException {
        DataInputStream dis = new DataInputStream(new ByteArrayInputStream(data));

        byte[] R    = readBytes(dis);
        byte[] CHK  = readBytes(dis);
        byte[] PATH = readBytes(dis);

        int chains = dis.readInt();
        int steps  = dis.readInt();
        byte[][][] sk = new byte[chains][steps][];
        for (int i = 0; i < chains; i++) {
            for (int j = 0; j < steps; j++) {
                sk[i][j] = readBytes(dis);
            }
        }

        return new CRV(R, CHK, PATH, sk);
    }

    // -------------------------------------------------------------------------

    private static void writeBytes(DataOutputStream dos, byte[] data) throws IOException {
        dos.writeInt(data.length);
        dos.write(data);
    }

    private static byte[] readBytes(DataInputStream dis) throws IOException {
        int len = dis.readInt();
        byte[] data = new byte[len];
        dis.readFully(data);
        return data;
    }
}