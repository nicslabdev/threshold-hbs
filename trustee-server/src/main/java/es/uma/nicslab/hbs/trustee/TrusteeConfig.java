package es.uma.nicslab.hbs.trustee;

import java.io.*;
import java.nio.file.*;

/**
 * Configuración del esquema del Trustee.
 *
 * Guarda la PRF_key que le llega en el SetupRequest y la persiste
 * en un fichero binario en el volumen Docker. Si el contenedor se reinicia,
 * el trustee puede reconstruir su estado leyendo este fichero.
 *
 * Formato del fichero (DataOutputStream, big-endian):
 *
 *   [int]    longitud de K
 *   [bytes]  K (clave PRF secreta)
 *
 * IMPORTANTE: este fichero contiene la clave PRF K, que es material
 * criptográfico sensible. En producción debe estar en un volumen Docker
 * con permisos restringidos (chmod 600).
 */
public class TrusteeConfig {

    private final byte[] K;

    public TrusteeConfig(byte[] K) {
        this.K = K.clone();
    }

    /**
     * Serializa la configuración a un fichero binario.
     *
     * @param path Ruta del fichero de salida, p.ej. "/db/trustee-config.bin".
     */
    public void saveTo(Path path) throws IOException {
        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        DataOutputStream dos = new DataOutputStream(baos);

        writeBytes(dos, K);

        dos.flush();

        // Escritura atómica: primero a fichero temporal, luego rename.
        Path tmp = path.resolveSibling(path.getFileName() + ".tmp");
        try {
            Files.write(tmp, baos.toByteArray(),
                    StandardOpenOption.CREATE,
                    StandardOpenOption.TRUNCATE_EXISTING);
            Files.move(tmp, path,
                    StandardCopyOption.ATOMIC_MOVE,
                    StandardCopyOption.REPLACE_EXISTING);
        } catch (IOException e) {
            Files.deleteIfExists(tmp);
            throw e;
        }
    }

    /**
     * Deserializa la configuración desde un fichero binario.
     *
     * @param path Ruta del fichero, p.ej. "/db/trustee-config.bin".
     * @return TrusteeConfig reconstruido.
     * @throws NoSuchFileException Si el fichero no existe (trustee no inicializado).
     */
    public static TrusteeConfig loadFrom(Path path) throws IOException {
        byte[] data = Files.readAllBytes(path);
        DataInputStream dis = new DataInputStream(new ByteArrayInputStream(data));

        byte[] K = readBytes(dis);

        return new TrusteeConfig(K);
    }

    /**
     * Indica si el fichero de configuración existe, es decir,
     * si el trustee ya ha sido inicializado mediante Setup.
     */
    public static boolean exists(Path path) {
        return Files.exists(path);
    }

    public byte[] getK() {
        return K.clone();
    }

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