package com.bsep.pki_system.service;

import com.bsep.pki_system.dto.CertificateIssueDTO;
import com.bsep.pki_system.dto.KeyStoreEntry;
import com.bsep.pki_system.exceptions.CertificateGenerationException;
import com.bsep.pki_system.model.*;
import com.bsep.pki_system.model.Certificate;
import com.bsep.pki_system.repository.CertificateRepository;
import com.bsep.pki_system.repository.KeystoreRepository;
import com.bsep.pki_system.repository.UserRepository;
import jakarta.annotation.PostConstruct;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x500.X500NameBuilder;
import org.bouncycastle.asn1.x500.style.BCStyle;
import org.bouncycastle.asn1.x509.KeyUsage;
import org.bouncycastle.cert.CertIOException;
import org.bouncycastle.cert.X509v3CertificateBuilder;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.HttpStatus;
import org.springframework.stereotype.Service;
import org.springframework.web.server.ResponseStatusException;

import javax.crypto.SecretKey;
import java.io.*;
import java.math.BigInteger;
import java.security.*;
import java.security.cert.CertificateEncodingException;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.time.ZoneId;
import java.time.ZonedDateTime;
import java.util.*;

@Service
public class CertificateService {
    private final CertificateRepository certificateRepository;
    private final UserRepository userRepository;
    private final CryptoService cryptoService;
    private final KeystoreRepository keystoreRepository;

    @Value("${aes.master.key}")
    private String masterKeyBase64;

    private SecretKey masterKey;

    public CertificateService(CertificateRepository certificateRepository, UserRepository userRepository, CryptoService cryptoService, KeystoreRepository keystoreRepository) {
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

            if (!adminUser.getRole().equals(UserRole.ADMIN)) {
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

            Certificate certificate = saveCertToDb(cert, adminUser, CertificateType.ROOT, keystore);

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

    private Certificate saveCertToDb(X509Certificate cert, User user, CertificateType type, Keystore keystore) {
        Certificate newCert = new Certificate();
        newCert.setSerialNumber(cert.getSerialNumber().toString());
        newCert.setAlias(cert.getSerialNumber().toString());
        newCert.setIssuer(cert.getIssuerX500Principal().getName());
        newCert.setSubject(cert.getSubjectX500Principal().getName());
        newCert.setValidFrom(cert.getNotBefore().toInstant().atZone(ZoneId.systemDefault()).toLocalDateTime());
        newCert.setValidTo(cert.getNotAfter().toInstant().atZone(ZoneId.systemDefault()).toLocalDateTime());
        newCert.setType(type);
        newCert.setOwner(user);
        newCert.setKeystore(keystore);

        certificateRepository.save(newCert);

        return newCert;
    }

    public String convertToPEM(X509Certificate certificate) throws CertificateEncodingException {
        StringBuilder pem = new StringBuilder();
        pem.append("-----BEGIN CERTIFICATE-----\n");
        pem.append(Base64.getMimeEncoder(64, "\n".getBytes()).encodeToString(certificate.getEncoded()));
        pem.append("\n-----END CERTIFICATE-----\n");
        return pem.toString();
    }

    public void issueCACertificate(CertificateIssueDTO issue, Long issuerId) throws Exception {
        Certificate signingCertificate = certificateRepository.findById(issue.getIssuerCertificateId())
                .orElseThrow(() -> new RuntimeException("Certificate not found"));

        User subject = userRepository.findById(issue.getSubjectId())
                .orElseThrow(() -> new CertificateGenerationException("CA user not found", null));

        if (subject.getRole() != UserRole.CA)
            throw new ResponseStatusException(HttpStatus.BAD_REQUEST, "Belaj user");

        Long signingCertificateOwnerId = signingCertificate.getOwner().getId();
        if (!signingCertificateOwnerId.equals(issuerId))
            throw new ResponseStatusException(HttpStatus.BAD_REQUEST, "Belaj");

        if (!(issue.getValidFrom().isBefore(issue.getValidTo())
                && issue.getValidFrom().isAfter(signingCertificate.getValidFrom())
                && issue.getValidTo().isBefore(signingCertificate.getValidTo())))
            throw new ResponseStatusException(HttpStatus.BAD_REQUEST, "Belaj datum");

        Keystore keystore = keystoreRepository.findById(signingCertificate.getKeystore().getId())
                .orElseThrow(() -> new CertificateGenerationException("Keystore not found", null));

        KeyStore ks = KeyStore.getInstance("PKCS12");
        String decryptedPassword = cryptoService.decryptAES(keystore.getEncryptedPassword(), masterKey);

        try (FileInputStream fis = new FileInputStream("certificates/keystore_" + keystore.getId() + ".p12")) {
            ks.load(fis, decryptedPassword.toCharArray());
        }

        String alias = signingCertificate.getAlias();

        // Load issuer's private key
        PrivateKey issuerPrivateKey = (PrivateKey) ks.getKey(alias, decryptedPassword.toCharArray());

        // Convert issuer chain to BC X509Certificate
        List<X509Certificate> issuerChainBC = new ArrayList<>();
        CertificateFactory cf = CertificateFactory.getInstance("X.509", "BC");
        for (java.security.cert.Certificate c : ks.getCertificateChain(alias)) {
            byte[] encoded = c.getEncoded();
            X509Certificate bcCert = (X509Certificate) cf.generateCertificate(new ByteArrayInputStream(encoded));
            issuerChainBC.add(bcCert);
        }

        BigInteger serial = BigInteger.valueOf(System.currentTimeMillis());
        KeyPair keyPair = cryptoService.generateRSAKeyPair();
        X500Name subjectInformation = buildSubject(issue);

        // Build the new certificate
        X509v3CertificateBuilder certificateBuilder = new JcaX509v3CertificateBuilder(
                new X500Name(signingCertificate.getSubject()),
                serial,
                Date.from(issue.getValidFrom().atZone(ZoneId.systemDefault()).toInstant()),
                Date.from(issue.getValidTo().atZone(ZoneId.systemDefault()).toInstant()),
                subjectInformation,
                keyPair.getPublic()
        );

        certificateBuilder.addExtension(
                org.bouncycastle.asn1.x509.Extension.basicConstraints,
                true,
                new org.bouncycastle.asn1.x509.BasicConstraints(true) // CA = true
        );

        int keyUsageBits = getKeyUsageBits(issue);
        if (keyUsageBits != 0) {
            certificateBuilder.addExtension(
                    org.bouncycastle.asn1.x509.Extension.keyUsage,
                    true,
                    new org.bouncycastle.asn1.x509.KeyUsage(keyUsageBits)
            );
        }

        ContentSigner signer = new JcaContentSignerBuilder("SHA256withRSA").build(issuerPrivateKey);
        X509Certificate newCert = new JcaX509CertificateConverter().setProvider("BC")
                .getCertificate(certificateBuilder.build(signer));

        // Build the final chain: new certificate + issuer chain (all BC)
        List<X509Certificate> chain = new ArrayList<>();
        chain.add(newCert);          // subject certificate first
        chain.addAll(issuerChainBC); // issuer certificates

        // Store in keystore
        ks.setKeyEntry(newCert.getSerialNumber().toString(), keyPair.getPrivate(),
                decryptedPassword.toCharArray(), chain.toArray(new X509Certificate[0]));

        try (FileOutputStream fos = new FileOutputStream("certificates/keystore_" + keystore.getId() + ".p12")) {
            ks.store(fos, decryptedPassword.toCharArray());
        }

        saveCertToDb(newCert, subject, CertificateType.INTERMEDIATE, keystore);
    }


    private X500Name buildSubject(CertificateIssueDTO dto) {
        X500NameBuilder builder = new X500NameBuilder(BCStyle.INSTANCE);

        if (dto.getCommonName() != null && !dto.getCommonName().isEmpty()) {
            builder.addRDN(BCStyle.CN, dto.getCommonName());
        }
        if (dto.getOrganization() != null && !dto.getOrganization().isEmpty()) {
            builder.addRDN(BCStyle.O, dto.getOrganization());
        }
        if (dto.getOrganizationalUnit() != null && !dto.getOrganizationalUnit().isEmpty()) {
            builder.addRDN(BCStyle.OU, dto.getOrganizationalUnit());
        }
        if (dto.getCountry() != null && !dto.getCountry().isEmpty()) {
            builder.addRDN(BCStyle.C, dto.getCountry());
        }
        if (dto.getState() != null && !dto.getState().isEmpty()) {
            builder.addRDN(BCStyle.ST, dto.getState());
        }
        if (dto.getLocality() != null && !dto.getLocality().isEmpty()) {
            builder.addRDN(BCStyle.L, dto.getLocality());
        }
        if (dto.getEmail() != null && !dto.getEmail().isEmpty()) {
            builder.addRDN(BCStyle.EmailAddress, dto.getEmail());
        }

        return builder.build();
    }

    private int getKeyUsageBits(CertificateIssueDTO issue) {
        List<KeyUsageType> usages = issue.getKeyUsages();
        if (usages == null || usages.isEmpty()) {
            return 0; // no key usages selected
        }

        int bits = 0;
        for (KeyUsageType usage : usages) {
            switch (usage) {
                case DIGITAL_SIGNATURE:
                    bits |= KeyUsage.digitalSignature;
                    break;
                case NON_REPUDIATION:
                    bits |= KeyUsage.nonRepudiation;
                    break;
                case KEY_ENCIPHERMENT:
                    bits |= KeyUsage.keyEncipherment;
                    break;
                case DATA_ENCIPHERMENT:
                    bits |= KeyUsage.dataEncipherment;
                    break;
                case KEY_AGREEMENT:
                    bits |= KeyUsage.keyAgreement;
                    break;
                case KEY_CERT_SIGN:
                    bits |= KeyUsage.keyCertSign;
                    break;
                case CRL_SIGN:
                    bits |= KeyUsage.cRLSign;
                    break;
                case ENCIPHER_ONLY:
                    bits |= KeyUsage.encipherOnly;
                    break;
                case DECIPHER_ONLY:
                    bits |= KeyUsage.decipherOnly;
                    break;
            }
        }

        return bits;
    }
}
