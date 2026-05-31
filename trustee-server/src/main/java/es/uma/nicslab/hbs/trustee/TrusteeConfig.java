package es.uma.nicslab.hbs.trustee;

import es.uma.nicslab.hbs.lms.LMOtsParameters;

import java.io.*;
import java.nio.file.*;

/**
 * Configuración del esquema del Trustee.
 *
 * Agrupa los siete parámetros que llegan en el SetupRequest y los persiste
 * en un fichero binario en el volumen Docker. Si el contenedor se reinicia,
 * el trustee puede reconstruir su estado leyendo este fichero.
 *
 * Formato del fichero (DataOutputStream, big-endian):
 *
 *   [int]    longitud de K
 *   [bytes]  K (clave PRF secreta)
 *   [int]    lmots_param_type
 *   [int]    longitud de I
 *   [bytes]  I (identificador árbol Merkle)
 *   [int]    length_chk
 *   [int]    length_path
 *   [int]    longitud de cas_url en UTF-8
 *   [bytes]  cas_url
 *   [int]    longitud de cl_cid en UTF-8
 *   [bytes]  cl_cid
 *
 * IMPORTANTE: este fichero contiene la clave PRF K, que es material
 * criptográfico sensible. En producción debe estar en un volumen Docker
 * con permisos restringidos (chmod 600).
 */
public class TrusteeConfig {

    private final byte[] K;
    private final int lmotsParamType;
    private final byte[] I;
    private final int lengthCHK;
    private final int lengthPath;
    private final String casUrl;
    private final String clCid;

    public TrusteeConfig(byte[] K, int lmotsParamType, byte[] I, int lengthCHK, int lengthPath, String casUrl, String clCid) {
        this.K = K.clone();
        this.lmotsParamType = lmotsParamType;
        this.I = I.clone();
        this.lengthCHK = lengthCHK;
        this.lengthPath = lengthPath;
        this.casUrl = casUrl;
        this.clCid = clCid;
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
        dos.writeInt(lmotsParamType);
        writeBytes(dos, I);
        dos.writeInt(lengthCHK);
        dos.writeInt(lengthPath);
        writeString(dos, casUrl);
        writeString(dos, clCid);

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
        int lmotsParamType = dis.readInt();
        byte[] I = readBytes(dis);
        int lengthCHK = dis.readInt();
        int lengthPath = dis.readInt();
        String casUrl = readString(dis);
        String clCid = readString(dis);

        return new TrusteeConfig(K, lmotsParamType, I, lengthCHK, lengthPath, casUrl, clCid);
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

    public int getLmotsParamType() {
        return lmotsParamType;
    }

    public byte[] getI() {
        return I.clone();
    }

    public int getLengthCHK() {
        return lengthCHK;
    }

    public int getLengthPath() {
        return lengthPath;
    }

    public String getCasUrl() {
        return casUrl;
    }

    public String getClCid() {
        return clCid;
    }

    /**
     * Reconstruye el objeto LMOtsParameters a partir del tipo almacenado.
     */
    public LMOtsParameters getLmotsParameters() {
        return LMOtsParameters.getParametersForType(lmotsParamType);
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

    private static void writeString(DataOutputStream dos, String s) throws IOException {
        byte[] bytes = s.getBytes(java.nio.charset.StandardCharsets.UTF_8);
        dos.writeInt(bytes.length);
        dos.write(bytes);
    }

    private static String readString(DataInputStream dis) throws IOException {
        int len = dis.readInt();
        byte[] bytes = new byte[len];
        dis.readFully(bytes);
        return new String(bytes, java.nio.charset.StandardCharsets.UTF_8);
    }
}