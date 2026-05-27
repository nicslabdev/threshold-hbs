package es.uma.nicslab.hbs.cas;

import java.io.IOException;
import java.nio.file.Path;
import java.nio.file.Paths;

public class CASManualTest {

    public static void main(String[] args) throws IOException {
        // Guarda los blobs en un directorio visible en mi ordenador
        Path dir = Paths.get("C:\\Users\\isabe\\OneDrive\\Escritorio\\Isabel\\NicsLab\\threshold-hbs\\cas-test");
        BlobStore store = new BlobStore(dir);

        // Simula lo que haría el Dealer al subir un CRV
        byte[] crvFalso = "hola isaac".getBytes();
        String cid = store.put(crvFalso);
        System.out.println("CID generado: " + cid);
        System.out.println("Fichero guardado en: " + dir + "/" + cid + ".blob");

        // Simula lo que haría el Aggregator al descargarlo
        byte[] recuperado = store.get(cid);
        System.out.println("Contenido recuperado: " + new String(recuperado));
        System.out.println("Integridad verificada: " + store.verify(cid));
    }
}