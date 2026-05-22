package es.uma.nicslab.hbs.cas;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardOpenOption;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.HexFormat;

/**
 * Almacenamiento de blobs direccionado por contenido (CAS).
 *
 * Cada blob se identifica por el SHA-256 de su contenido (CID).
 * El blob se persiste en disco como un fichero cuyo nombre es el CID.
 *
 * Propiedades:
 *  - Idempotente: subir el mismo blob dos veces produce el mismo CID
 *    sin duplicar el fichero en disco.
 *  - Verificable: cualquier caller puede recalcular el SHA-256 del blob
 *    recibido y compararlo con el CID solicitado.
 *  - Sin estado adicional: no hay base de datos ni índice; el directorio
 *    de datos ES el índice.
 */
public class BlobStore {

    private static final String EXTENSION = ".blob";
    private final Path dataDir;

    /**
     * @param dataDir Directorio donde se persisten los blobs.
     *                Se crea automáticamente si no existe.
     */
    public BlobStore(Path dataDir) throws IOException {
        this.dataDir = dataDir;
        Files.createDirectories(dataDir);
    }

    /**
     * Almacena un blob y devuelve su CID (SHA-256 en hexadecimal).
     *
     * Si el blob ya existe en disco (mismo CID), no se sobreescribe
     * y se devuelve el CID directamente.
     *
     * @param blob Contenido a almacenar. No puede ser null ni vacío.
     * @return CID: SHA-256 del contenido en hexadecimal lowercase (64 chars).
     */
    public String put(byte[] blob) throws IOException {
        if (blob == null || blob.length == 0) {
            throw new IllegalArgumentException("El blob no puede ser null ni vacío");
        }

        String cid = sha256hex(blob);
        Path target = blobPath(cid);

        if (!Files.exists(target)) {
            // Escritura atómica: primero a fichero temporal, luego rename.
            // Evita que un crash deje un fichero corrupto con el nombre del CID.
            Path tmp = dataDir.resolve(cid + ".tmp");
            try {
                // Escribe los bytes de blob en la ruta del archivo temporal tmp.
                // La opción CREATE dice que cree el archivo si no existe.
                // La opción TRUNCATE_EXISTING dice que si ya existía el temporal, borre su contenido anterior para escribir el nuevo desde cero.
                Files.write(tmp, blob, StandardOpenOption.CREATE,
                        StandardOpenOption.TRUNCATE_EXISTING);
                // Mueve el archivo temporal a su ubicación y le pone el nombre definitivo.
                // ATOMIC_MOVE garantiza que la operación se realiza en un solo paso indivisible a nivel de sistema operativo.
                // REPLACE_EXISTING indica que si ya hubiese algo ahí, lo reemplace.
                Files.move(tmp, target,
                        java.nio.file.StandardCopyOption.ATOMIC_MOVE,
                        java.nio.file.StandardCopyOption.REPLACE_EXISTING);
            } catch (IOException e) {
                Files.deleteIfExists(tmp);
                throw e;
            }
        }

        return cid;
    }

    /**
     * Recupera un blob por su CID.
     *
     * @param cid SHA-256 en hexadecimal (64 chars lowercase).
     * @return Contenido del blob.
     * @throws BlobNotFoundException Si no existe ningún blob con ese CID.
     */
    public byte[] get(String cid) throws IOException {
        validateCid(cid);
        Path target = blobPath(cid);

        if (!Files.exists(target)) {
            throw new BlobNotFoundException(cid);
        }

        return Files.readAllBytes(target);
    }

    /**
     * Verifica que el blob almacenado bajo un CID no ha sido alterado.
     * Recalcula el SHA-256 del contenido leído y lo compara con el CID.
     *
     * Útil para que el aggregator compruebe la integridad del CRV
     * descargado del CAS.
     *
     * @return true si el contenido es íntegro, false si ha sido alterado.
     */
    public boolean verify(String cid) throws IOException {
        byte[] blob = get(cid);
        return cid.equals(sha256hex(blob));
    }

    /**
     * Comprueba si existe un blob con el CID dado, sin leerlo.
     */
    public boolean exists(String cid) {
        validateCid(cid);
        return Files.exists(blobPath(cid));
    }

    // -------------------------------------------------------------------------
    // Métodos privados
    // -------------------------------------------------------------------------

    private Path blobPath(String cid) {
        return dataDir.resolve(cid + EXTENSION);
    }

    private static String sha256hex(byte[] data) {
        try {
            MessageDigest digest = MessageDigest.getInstance("SHA-256");
            byte[] hash = digest.digest(data);
            return HexFormat.of().formatHex(hash);
        } catch (NoSuchAlgorithmException e) {
            // SHA-256 está garantizado en cualquier JVM (java.security)
            throw new IllegalStateException("SHA-256 no disponible", e);
        }
    }

    private static void validateCid(String cid) {
        if (cid == null || cid.length() != 64 || !cid.matches("[0-9a-f]+")) {
            throw new IllegalArgumentException(
                    "CID inválido (debe ser SHA-256 hex lowercase de 64 chars): " + cid);
        }
    }

    // -------------------------------------------------------------------------
    // Excepción checked específica del CAS
    // -------------------------------------------------------------------------

    public static class BlobNotFoundException extends IOException {
        private final String cid;

        public BlobNotFoundException(String cid) {
            super("Blob no encontrado para CID: " + cid);
            this.cid = cid;
        }

        public String getCid() {
            return cid;
        }
    }
}