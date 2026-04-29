package es.uma.nicslab.hbs.util;

import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.X509v3CertificateBuilder;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.crypto.AsymmetricCipherKeyPair;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.pqc.crypto.lms.*;
import org.bouncycastle.openssl.jcajce.JcaPEMWriter;
import org.bouncycastle.pqc.jcajce.provider.BouncyCastlePQCProvider;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.pqc.crypto.util.SubjectPublicKeyInfoFactory;

import java.io.*;
import java.math.BigInteger;
import java.nio.file.Files;
import java.security.*;
import java.security.cert.X509Certificate;
import java.util.Date;

public class LMSExporterOpenSSL {

    static {
        Security.addProvider(new BouncyCastlePQCProvider());
        Security.addProvider(new org.bouncycastle.jce.provider.BouncyCastleProvider());
    }

    public static void main(String[] args) throws Exception {

        // 1. Generar par de claves LMS
        LMSKeyGenerationParameters genParams = new LMSKeyGenerationParameters(
                new LMSParameters(LMSigParameters.lms_sha256_n32_h5,
                        LMOtsParameters.sha256_n32_w4),
                new SecureRandom()
        );

        LMSKeyPairGenerator gen = new LMSKeyPairGenerator();
        gen.init(genParams);
        AsymmetricCipherKeyPair keyPair = gen.generateKeyPair();

        LMSPrivateKeyParameters privateKey = (LMSPrivateKeyParameters) keyPair.getPrivate();
        LMSPublicKeyParameters publicKey  = (LMSPublicKeyParameters)  keyPair.getPublic();

        // 2. Firmar un mensaje
        byte[] message = "Hola OpenSSL".getBytes();
        LMSSigner signer = new LMSSigner();
        signer.init(true, privateKey);
        byte[] signature = signer.generateSignature(message);

        // 3. Exportar clave pública en PEM (lo que OpenSSL espera con -pubin)
        exportPublicKeyToPEM(publicKey, "lmspub.pem");

        // 4. Exportar firma como bytes raw
        exportSignatureRaw(signature, "sig.file");

        // 5. Exportar mensaje (el -in de pkeyutl)
        Files.write(java.nio.file.Paths.get("message.bin"), message);

        // 6. Exportar certificado X.509 autofirmado
        exportCertificate(publicKey, privateKey, "cert.pem");

        System.out.println("Archivos generados: lmspub.pem, sig.file, message.bin, cert.pem");
        System.out.println("Verificar con:");
        System.out.println("  openssl pkeyutl -verify -in message.bin -sigfile sig.file -inkey lmspub.pem -pubin");
        System.out.println("Inspeccionar certificado con:");
        System.out.println("  openssl x509 -in cert.pem -text -noout");
    }

    /**
     * Exporta la clave pública LMS en formato PEM (SubjectPublicKeyInfo).
     * Esto es lo que JcaPEMWriter sabe manejar correctamente.
     */
    static void exportPublicKeyToPEM(LMSPublicKeyParameters pub, String path)
            throws Exception {
        // Convertir a SubjectPublicKeyInfo (formato X.509 estándar)
        SubjectPublicKeyInfo spki = SubjectPublicKeyInfoFactory.createSubjectPublicKeyInfo(pub);

        try (JcaPEMWriter writer = new JcaPEMWriter(new FileWriter(path))) {
            writer.writeObject(spki);
        }
        System.out.println("Clave pública exportada a: " + path);
    }

    /**
     * La firma LMS es simplemente bytes raw según RFC 8554.
     * OpenSSL los lee directamente con -sigfile.
     * No hay encapsulamiento PEM necesario aquí.
     */
    static void exportSignatureRaw(byte[] signature, String path) throws Exception {
        Files.write(java.nio.file.Paths.get(path), signature);
        System.out.println("Firma exportada a: " + path);
    }

    static void exportCertificate(LMSPublicKeyParameters pub,
                                  LMSPrivateKeyParameters priv,
                                  String path) throws Exception {

        // Convertir clave pública lightweight → SubjectPublicKeyInfo
        SubjectPublicKeyInfo spki = SubjectPublicKeyInfoFactory.createSubjectPublicKeyInfo(pub);

        // Fechas de validez: ahora hasta +1 año
        Date notBefore = new Date();
        Date notAfter  = new Date(notBefore.getTime() + 365L * 24 * 60 * 60 * 1000);

        // Construir el certificado
        X509v3CertificateBuilder certBuilder = new X509v3CertificateBuilder(
                new X500Name("CN=LMS Test Issuer, O=BouncyCastle, C=ES"),  // Issuer
                BigInteger.valueOf(System.currentTimeMillis()),         // Número de serie
                notBefore,
                notAfter,
                new X500Name("CN=LMS Test Subject, O=BouncyCastle, C=ES"), // Subject
                spki
        );

        // ContentSigner: firma el certificado con la clave privada LMS
        // usando la Lightweight API de BC directamente
        ContentSigner contentSigner = new ContentSigner() {
            private final ByteArrayOutputStream buffer = new ByteArrayOutputStream();

            @Override
            public org.bouncycastle.asn1.x509.AlgorithmIdentifier getAlgorithmIdentifier() {
                // OID de LMS: id-alg-hss-lms-hashsig
                return new org.bouncycastle.asn1.x509.AlgorithmIdentifier(
                        new org.bouncycastle.asn1.ASN1ObjectIdentifier("1.2.840.113549.1.9.16.3.17")
                );
            }

            @Override
            public OutputStream getOutputStream() {
                return buffer;
            }

            @Override
            public byte[] getSignature() {
                try {
                    LMSSigner certSigner = new LMSSigner();
                    certSigner.init(true, priv);
                    return certSigner.generateSignature(buffer.toByteArray());
                } catch (Exception e) {
                    throw new RuntimeException("Error firmando certificado", e);
                }
            }
        };

        // Generar el holder y convertir a X509Certificate
        X509CertificateHolder holder = certBuilder.build(contentSigner);
        X509Certificate cert = new JcaX509CertificateConverter()
                .setProvider("BC")
                .getCertificate(holder);

        // Exportar a PEM
        try (JcaPEMWriter writer = new JcaPEMWriter(new FileWriter(path))) {
            writer.writeObject(cert);
        }
        System.out.println("Certificado exportado a: " + path);
    }

}