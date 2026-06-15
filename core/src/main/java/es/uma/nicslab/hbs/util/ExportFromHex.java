package es.uma.nicslab.hbs.util;

import org.bouncycastle.pqc.crypto.lms.LMSPublicKeyParameters;
import java.util.HexFormat;

public class ExportFromHex {
    public static void main(String[] args) throws Exception {
        String hex = "000000050000000376c7743c174b4ba46176ef968a38ac1c6db730898bbb8272c66b9a70316711ef32d77dd0eb42e8094521f7de4729aa4a";

        byte[] keyBytes = HexFormat.of().parseHex(hex);
        LMSPublicKeyParameters pub = LMSPublicKeyParameters.getInstance(keyBytes);

        LMSExporterOpenSSL.exportPublicKeyToPEM(pub, "lmspublickey.pem");
        System.out.println("Exportado correctamente.");
    }
}