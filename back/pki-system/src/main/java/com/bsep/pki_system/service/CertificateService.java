package com.bsep.pki_system.service;

import com.bsep.pki_system.exceptions.CertificateGenerationException;
import com.bsep.pki_system.model.*;
import com.bsep.pki_system.model.Certificate;
import com.bsep.pki_system.repository.CertificateRepository;
import com.bsep.pki_system.repository.UserRepository;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.cert.CertIOException;
import org.bouncycastle.cert.X509v3CertificateBuilder;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.springframework.stereotype.Service;

import javax.crypto.SecretKey;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.math.BigInteger;
import java.security.*;
import java.security.cert.CertificateEncodingException;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.time.ZoneId;
import java.time.ZonedDateTime;
import java.util.Base64;

@Service
public class CertificateService {
    private final CertificateRepository certificateRepository;
    private final UserRepository userRepository;
    private final CryptoService cryptoService;

    public CertificateService(CertificateRepository certificateRepository, UserRepository userRepository, CryptoService cryptoService) {
        this.certificateRepository = certificateRepository;
        this.userRepository = userRepository;
        this.cryptoService = cryptoService;
    }

    public X509Certificate loadCertificateFromKeystore(long adminId,String alias) {
        try {
            User adminUser = userRepository.findById(adminId)
                    .orElseThrow(() -> new CertificateGenerationException("Admin user not found", null));

            if(!adminUser.getRole().equals(UserRole.ADMIN)){
                throw new CertificateGenerationException("User is not allowed to generate certificates", null);
            }

            KeyStore ks = KeyStore.getInstance("PKCS12");

            SecretKey restoredKey = cryptoService.decodeAESKey(adminUser.getAesKey());
            String decryptedPassword = cryptoService.decryptAES(adminUser.getKeystorePassword(), restoredKey);

            try (FileInputStream fis = new FileInputStream("certificates/" + alias + ".p12")) {
                ks.load(fis, decryptedPassword.toCharArray());
            }

            return (X509Certificate) ks.getCertificate(alias);
        } catch (Exception e) {
            throw new CertificateGenerationException("Failed to load certificate from keystore", e);
        }
    }

    public Certificate generateRootCertificate(long adminId) {
        try {
            User adminUser = userRepository.findById(adminId)
                    .orElseThrow(() -> new CertificateGenerationException("Admin user not found", null));

            if(!adminUser.getRole().equals(UserRole.ADMIN)){
                throw new CertificateGenerationException("User is not allowed to generate certificates", null);
            }

            String alias = "rootCA";

            if (rootKeystoreExists(alias)) {
                throw new CertificateGenerationException("Root CA keystore already exists", null);
            }

            KeyPair keyPair = cryptoService.generateRSAKeyPair();

            X509Certificate cert = buildRootCertificate(keyPair);

            // generisanje random encryptovane sifre
            String plainPassword = "randomPassword123";
            SecretKey aesKey = cryptoService.generateAESKey();
            String aesKeyBase64 = cryptoService.encodeKey(aesKey);
            String encryptedPassword = cryptoService.encryptAES(plainPassword, aesKey);

            adminUser.setKeystorePassword(encryptedPassword);
            adminUser.setAesKey(aesKeyBase64);

            storeRootKeystore(cert, keyPair.getPrivate(), alias, plainPassword.toCharArray());

            return saveCertToDb(cert, adminUser, alias);

        } catch (Exception e) {
            throw new CertificateGenerationException("Failed to generate root certificate", e);
        }
    }

    private X509Certificate buildRootCertificate(KeyPair keyPair) throws CertIOException, CertificateException, OperatorCreationException {
        X500Name issuer = new X500Name("CN=MyRootCA,O=MyOrg");
        BigInteger serial = BigInteger.valueOf(System.currentTimeMillis());

        ZonedDateTime now = ZonedDateTime.now();
        ZonedDateTime expiry = now.plusYears(20);

        X509v3CertificateBuilder certBuilder = new JcaX509v3CertificateBuilder(
                issuer,
                serial,
                java.util.Date.from(now.toInstant()),
                java.util.Date.from(expiry.toInstant()),
                issuer, // samo potpisani
                keyPair.getPublic()
        );

        // CA = true
        certBuilder.addExtension(
                org.bouncycastle.asn1.x509.Extension.basicConstraints,
                true,
                new org.bouncycastle.asn1.x509.BasicConstraints(true)
        );

        // Potpis privatnim klj
        ContentSigner signer = new JcaContentSignerBuilder("SHA256withRSA").build(keyPair.getPrivate());
        X509Certificate cert = new JcaX509CertificateConverter().setProvider("BC")
                .getCertificate(certBuilder.build(signer));

        return cert;
    }

    private boolean rootKeystoreExists(String alias) {
        File certDir = new File("certificates");
        if (!certDir.exists()) {
            return false;
        }

        File keystoreFile = new File(certDir, alias + ".p12");
        return keystoreFile.exists();
    }

    private void storeRootKeystore(X509Certificate cert, PrivateKey privateKey, String alias, char[] password)
            throws KeyStoreException, CertificateException, IOException, NoSuchAlgorithmException {

        File certDir = new File("certificates");
        File keystoreFile = new File(certDir, alias + ".p12");

        // New PKCS12 keystore
        KeyStore ks = KeyStore.getInstance("PKCS12");
        ks.load(null, null);

        // Store private key + certificate
        ks.setKeyEntry(alias, privateKey, password, new X509Certificate[]{cert});

        try (FileOutputStream fos = new FileOutputStream(keystoreFile)) {
            ks.store(fos, password);
        }

        System.out.println("Root CA keystore successfully created at: " + keystoreFile.getAbsolutePath());
    }

    private Certificate saveCertToDb(X509Certificate cert, User adminUser, String alias) {
        Certificate rootCert = new Certificate();
        rootCert.setAlias(alias);
        rootCert.setSerialNumber(cert.getSerialNumber().toString());
        rootCert.setIssuer(cert.getIssuerX500Principal().getName());
        rootCert.setSubject(cert.getSubjectX500Principal().getName());
        rootCert.setValidFrom(cert.getNotBefore().toInstant().atZone(ZoneId.systemDefault()).toLocalDateTime());
        rootCert.setValidTo(cert.getNotAfter().toInstant().atZone(ZoneId.systemDefault()).toLocalDateTime());
        rootCert.setStatus(CertificateStatus.ACTIVE);
        rootCert.setType(CertificateType.ROOT);
        rootCert.setOwner(adminUser);

        certificateRepository.save(rootCert);

        return rootCert;
    }

    public String convertToPEM(X509Certificate certificate) throws CertificateEncodingException {
        StringBuilder pem = new StringBuilder();
        pem.append("-----BEGIN CERTIFICATE-----\n");
        pem.append(Base64.getMimeEncoder(64, "\n".getBytes()).encodeToString(certificate.getEncoded()));
        pem.append("\n-----END CERTIFICATE-----\n");
        return pem.toString();
    }
}
