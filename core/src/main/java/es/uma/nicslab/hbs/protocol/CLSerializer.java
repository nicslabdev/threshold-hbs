package es.uma.nicslab.hbs.protocol;

import java.io.*;

/**
 * Serialización binaria de CoalitionEntry[] a byte[] y viceversa.
 *
 * Formato (big-endian, DataOutputStream):
 *
 *   [int]  número de entradas (D = cl.length)
 *   para cada entrada keyID:
 *     [int]    número de trustees de esta coalición
 *     [int]    trustee[0]
 *     [int]    trustee[1]
 *     ...
 *     [int]    longitud del crvCid en bytes UTF-8
 *     [bytes]  crvCid en UTF-8
 */
public class CLSerializer {

    private CLSerializer() {}

    public static byte[] serialize(CoalitionEntry[] cl) throws IOException {
        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        DataOutputStream dos = new DataOutputStream(baos);

        dos.writeInt(cl.length);
        for (CoalitionEntry entry : cl) {
            int[] trustees = entry.trustees();
            dos.writeInt(trustees.length);
            for (int t : trustees) {
                dos.writeInt(t);
            }
            byte[] cidBytes = entry.crvCid().getBytes(java.nio.charset.StandardCharsets.UTF_8);
            dos.writeInt(cidBytes.length);
            dos.write(cidBytes);
        }

        dos.flush();
        return baos.toByteArray();
    }

    public static CoalitionEntry[] deserialize(byte[] data) throws IOException {
        DataInputStream dis = new DataInputStream(new ByteArrayInputStream(data));

        int d = dis.readInt();
        CoalitionEntry[] cl = new CoalitionEntry[d];

        for (int keyID = 0; keyID < d; keyID++) {
            int numTrustees = dis.readInt();
            int[] trustees = new int[numTrustees];
            for (int i = 0; i < numTrustees; i++) {
                trustees[i] = dis.readInt();
            }
            int cidLen = dis.readInt();
            byte[] cidBytes = new byte[cidLen];
            dis.readFully(cidBytes);
            String crvCid = new String(cidBytes, java.nio.charset.StandardCharsets.UTF_8);
            cl[keyID] = new CoalitionEntry(trustees, crvCid);
        }

        return cl;
    }
}