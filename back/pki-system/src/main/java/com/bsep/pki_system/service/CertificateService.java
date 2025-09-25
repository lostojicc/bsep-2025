package com.bsep.pki_system.service;

import com.bsep.pki_system.exceptions.CertificateGenerationException;
import com.bsep.pki_system.model.*;
import com.bsep.pki_system.model.Certificate;
import com.bsep.pki_system.repository.CertificateRepository;
import com.bsep.pki_system.repository.KeystoreRepository;
import com.bsep.pki_system.repository.UserRepository;
import jakarta.annotation.PostConstruct;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.cert.CertIOException;
import org.bouncycastle.cert.X509v3CertificateBuilder;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.springframework.beans.factory.annotation.Value;
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
    private final KeystoreRepository  keystoreRepository;

    @Value("${aes.master.key}")
    private String masterKeyBase64;

    private SecretKey masterKey;

    public CertificateService(CertificateRepository certificateRepository, UserRepository userRepository, CryptoService cryptoService,  KeystoreRepository keystoreRepository) {
        this.certificateRepository = certificateRepository;
        this.userRepository = userRepository;
        this.cryptoService = cryptoService;
        this.keystoreRepository = keystoreRepository;
    }

    @PostConstruct
    public void init() {
        this.masterKey = cryptoService.decodeAESKey(masterKeyBase64);
    }

    public X509Certificate loadCertificateFromKeystore(String alias) {
        try {
            Certificate certificate = certificateRepository.findCertificateByAlias(alias)
                    .orElseThrow(() -> new CertificateGenerationException("Certificate not found", null));

            Keystore keystore = keystoreRepository.findById(certificate.getKeystore().getId())
                    .orElseThrow(() -> new CertificateGenerationException("Keystore not found", null));

            KeyStore ks = KeyStore.getInstance("PKCS12");

            String decryptedPassword = cryptoService.decryptAES(keystore.getEncryptedPassword(), masterKey);

            try (FileInputStream fis = new FileInputStream("certificates/keystore_" + keystore.getId() + ".p12")) {
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

            KeyPair keyPair = cryptoService.generateRSAKeyPair();

            X509Certificate cert = buildRootCertificate(keyPair);

            // generisanje random encryptovane sifre
            String plainPassword = cryptoService.generateRandomPassword();
            String encryptedPassword = cryptoService.encryptAES(plainPassword, masterKey);

            Keystore keystore = new Keystore();
            keystore.setEncryptedPassword(encryptedPassword);
            keystore = keystoreRepository.save(keystore);

            Certificate certificate = saveCertToDb(cert, adminUser, keystore);

            storeRootKeystore(cert, keyPair.getPrivate(), certificate.getAlias(), plainPassword.toCharArray(), keystore);

            return certificate;

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

        certBuilder.addExtension(
                org.bouncycastle.asn1.x509.Extension.keyUsage,
                true,
                new org.bouncycastle.asn1.x509.KeyUsage(
                        org.bouncycastle.asn1.x509.KeyUsage.keyCertSign
                                | org.bouncycastle.asn1.x509.KeyUsage.cRLSign
                )
        );

        // Potpis privatnim klj
        ContentSigner signer = new JcaContentSignerBuilder("SHA256withRSA").build(keyPair.getPrivate());
        X509Certificate cert = new JcaX509CertificateConverter().setProvider("BC")
                .getCertificate(certBuilder.build(signer));

        return cert;
    }

    private void storeRootKeystore(X509Certificate cert,
                                   PrivateKey privateKey,
                                   String alias,
                                   char[] password,
                                   Keystore keystore)
            throws KeyStoreException, CertificateException, IOException, NoSuchAlgorithmException {

        File certDir = new File("certificates");
        if (!certDir.exists()) {
            certDir.mkdirs();
        }

        File keystoreFile = new File(certDir, "keystore_" + keystore.getId() + ".p12");

        KeyStore ks = KeyStore.getInstance("PKCS12");
        ks.load(null, null);

        ks.setKeyEntry(alias, privateKey, password, new X509Certificate[]{cert});

        try (FileOutputStream fos = new FileOutputStream(keystoreFile)) {
            ks.store(fos, password);
        }

        System.out.println("Root CA keystore successfully created at: " + keystoreFile.getAbsolutePath());
    }

    private Certificate saveCertToDb(X509Certificate cert, User adminUser, Keystore keystore) {
        Certificate rootCert = new Certificate();
        rootCert.setSerialNumber(cert.getSerialNumber().toString());
        rootCert.setAlias(cert.getSerialNumber().toString());
        rootCert.setIssuer(cert.getIssuerX500Principal().getName());
        rootCert.setSubject(cert.getSubjectX500Principal().getName());
        rootCert.setValidFrom(cert.getNotBefore().toInstant().atZone(ZoneId.systemDefault()).toLocalDateTime());
        rootCert.setValidTo(cert.getNotAfter().toInstant().atZone(ZoneId.systemDefault()).toLocalDateTime());
        rootCert.setStatus(CertificateStatus.ACTIVE);
        rootCert.setType(CertificateType.ROOT);
        rootCert.setOwner(adminUser);
        rootCert.setKeystore(keystore);

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
