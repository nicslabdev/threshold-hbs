package es.uma.nicslab.hbs.protocol;

import es.uma.nicslab.hbs.lms.LMSPublicKeyParameters;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardCopyOption;
import java.nio.file.StandardOpenOption;
import java.util.HexFormat;

/**
 * Bulletin Board público del esquema threshold HBS.
 *
 *   {
 *   "lmsPublicKey": "3082...hex...",
 *   "clCid":        "a3f8b2...64chars...",
 *   "lengthCHK":    128,
 *   "lengthPath":   160
 *   }
 *
 * Este fichero es público: cualquiera
 * puede leerlo. Un attacker que lo modifique solo puede impedir firmas
 * válidas (dando una clave pública o CL incorrecta), pero no puede forjar
 * firmas porque no conoce las claves PRF de los trustees.
 *
 * En Docker, este fichero vive en un volumen compartido.
 */
public class BulletinBoard {

    private final LMSPublicKeyParameters lmsPublicKey;
    private final String clCid;
    private final int lengthCHK;
    private final int lengthPATH;


    public BulletinBoard(LMSPublicKeyParameters lmsPublicKey, String clCid, int lengthCHK, int lengthPATH) {
        this.lmsPublicKey = lmsPublicKey;
        this.clCid = clCid;
        this.lengthCHK = lengthCHK;
        this.lengthPATH = lengthPATH;
    }

    /**
     * Serializa el bulletin board a un fichero JSON.
     * Escritura atómica: primero a .tmp, luego rename.
     *
     * @param path Ruta del fichero, p.ej. "/bulletin/board.json".
     */
    public void saveTo(Path path) throws IOException {
        byte[] encoded = lmsPublicKey.getEncoded();
        String hex = HexFormat.of().formatHex(encoded);

        String json = "{\n" +
                "  \"lmsPublicKey\": \"" + hex + "\",\n" +
                "  \"clCid\": \"" + clCid + "\",\n" +
                "  \"lengthCHK\": " + lengthCHK + ",\n" +
                "  \"lengthPATH\": " + lengthPATH + "\n" +
                "}\n";

        Path tmp = path.resolveSibling(path.getFileName() + ".tmp");
        try {
            Files.createDirectories(path.getParent());
            Files.write(tmp, json.getBytes(StandardCharsets.UTF_8),
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
     * Deserializa el bulletin board desde un fichero JSON.
     *
     * @param path Ruta del fichero.
     * @return BulletinBoard reconstruido.
     */
    public static BulletinBoard loadFrom(Path path) throws IOException {
        String json = Files.readString(path, StandardCharsets.UTF_8);

        String lmsKeyHex = extractStringField(json, "lmsPublicKey");
        String clCid = extractStringField(json, "clCid");
        int lengthCHK = extractIntField(json, "lengthCHK");
        int lengthPATH = extractIntField(json, "lengthPATH");

        byte[] lmsKeyBytes = HexFormat.of().parseHex(lmsKeyHex);
        LMSPublicKeyParameters lmsPublicKey = LMSPublicKeyParameters.getInstance(lmsKeyBytes);

        return new BulletinBoard(lmsPublicKey, clCid, lengthCHK, lengthPATH);
    }

    /**
     * Indica si el fichero del bulletin board existe.
     */
    public static boolean exists(Path path) {
        return Files.exists(path);
    }

    public LMSPublicKeyParameters getLmsPublicKey() {
        return lmsPublicKey;
    }

    public String getClCid() {
        return clCid;
    }

    public int getLengthCHK() {
        return lengthCHK;
    }

    public int getLengthPATH() {
        return lengthPATH;
    }

    /**
     * Extrae el valor de un campo JSON de la forma "campo": "valor".
     * Suficiente para un JSON con dos campos de cadena simples.
     */
    private static String extractStringField(String json, String field) throws IOException {
        String key = "\"" + field + "\"";
        int keyIdx = json.indexOf(key);
        if (keyIdx < 0) {
            throw new IOException("Campo '" + field + "' no encontrado en el JSON");
        }
        int colonIdx = json.indexOf(':', keyIdx + key.length());
        int openIdx  = json.indexOf('"', colonIdx + 1);
        int closeIdx = json.indexOf('"', openIdx + 1);
        if (openIdx < 0 || closeIdx < 0) {
            throw new IOException("Valor del campo '" + field + "' malformado en el JSON");
        }
        return json.substring(openIdx + 1, closeIdx);
    }

    private static int extractIntField(String json, String field) throws IOException {
        String key = "\"" + field + "\"";
        int keyIdx = json.indexOf(key);
        if (keyIdx < 0) {
            throw new IOException("Campo '" + field + "' no encontrado en el JSON");
        }
        int colonIdx = json.indexOf(':', keyIdx + key.length());
        // Leer hasta la coma o el cierre de llave
        int start = colonIdx + 1;
        while (start < json.length() && Character.isWhitespace(json.charAt(start))) {
            start++;
        }
        int end = start;
        while (end < json.length() && (Character.isDigit(json.charAt(end)) || json.charAt(end) == '-')) {
            end++;
        }
        String valueStr = json.substring(start, end).trim();
        try {
            return Integer.parseInt(valueStr);
        } catch (NumberFormatException e) {
            throw new IOException("Valor entero del campo '" + field + "' malformado: " + valueStr);
        }
    }

}