package es.uma.nicslab.hbs.util;

import org.bouncycastle.pqc.crypto.lms.LMSPublicKeyParameters;

import java.util.HexFormat;

public class ExportFromHex {

    public static void main(String[] args) throws Exception {

        if (args.length != 2) {
            System.err.println(
                    "Usage: ExportFromHex <lms-public-key-hex> <output.pem>"
            );
            System.exit(2);
        }

        String hex = args[0];
        String outputPath = args[1];

        final byte[] keyBytes;

        try {
            keyBytes = HexFormat.of().parseHex(hex);
        } catch (IllegalArgumentException e) {
            System.err.println("ERROR: invalid hexadecimal LMS public key.");
            System.exit(2);
            return;
        }

        LMSPublicKeyParameters pub =
                LMSPublicKeyParameters.getInstance(keyBytes);

        LMSExporterOpenSSL.exportPublicKeyToPEM(
                pub,
                outputPath
        );

        System.out.println("Public key exported successfully.");
    }
}