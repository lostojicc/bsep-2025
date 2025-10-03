package com.bsep.pki_system.service;

import com.bsep.pki_system.dto.CertificateIssueDTO;
import com.bsep.pki_system.dto.KeyStoreEntry;
import com.bsep.pki_system.dto.CertificateDTO;
import com.bsep.pki_system.exceptions.CertificateGenerationException;
import com.bsep.pki_system.model.*;
import com.bsep.pki_system.model.Certificate;
import com.bsep.pki_system.repository.CertificateRepository;
import com.bsep.pki_system.repository.CsrRepository;
import com.bsep.pki_system.repository.KeystoreRepository;
import com.bsep.pki_system.repository.UserRepository;
import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.ObjectMapper;
import jakarta.annotation.PostConstruct;
import jakarta.transaction.Transactional;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x500.X500NameBuilder;
import org.bouncycastle.asn1.x500.style.BCStyle;
import org.bouncycastle.asn1.x509.BasicConstraints;
import org.bouncycastle.asn1.x509.Extension;
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
    private final CsrRepository csrRepository;
    private final ObjectMapper objectMapper = new ObjectMapper();

    @Value("${aes.master.key}")
    private String masterKeyBase64;

    private SecretKey masterKey;

    public CertificateService(CertificateRepository certificateRepository, UserRepository userRepository, CryptoService cryptoService, KeystoreRepository keystoreRepository, CsrRepository csrRepository) {
        this.certificateRepository = certificateRepository;
        this.userRepository = userRepository;
        this.cryptoService = cryptoService;
        this.keystoreRepository = keystoreRepository;
        this.csrRepository = csrRepository;
    }

    @PostConstruct
    public void init() {
        this.masterKey = cryptoService.decodeAESKey(masterKeyBase64);
    }

    public List<CertificateDTO> getAllOwnedCertificates(Long userId) {
        User user = userRepository.findById(userId)
                .orElseThrow(() -> new CertificateGenerationException("User not found", null));

        List<CertificateDTO> certificateDTOList = new ArrayList<>();

        List<Certificate> certificates = certificateRepository.findAllByOwnerOrderById(user);

        for(Certificate c : certificates) {
            certificateDTOList.add(new CertificateDTO(c, true));
        }

        return certificateDTOList;
    }

    public List<CertificateDTO> getAllCertificatesByKeystore(Long keystoreId) {
        Keystore keystore = keystoreRepository.findById(keystoreId)
                .orElseThrow(() -> new IllegalArgumentException("Keystore not found", null));

        List<CertificateDTO> certificateDTOList = new ArrayList<>();

        List<Certificate> certificates = certificateRepository.findAllByKeystoreOrderByType(keystore);

        for(Certificate c : certificates) {
            // da li admin sme da revokuje sve sertifikate ?
            certificateDTOList.add(new CertificateDTO(c, false));
        }

        return certificateDTOList;
    }

    @Transactional
    public CSR approveCsr(Long csrId, Long caUserId, Long signingCertificateId, String manualRejectionReason) throws Exception {
        CSR csr = csrRepository.findById(csrId)
                .orElseThrow(() -> new IllegalArgumentException("CSR not found"));

        if (csr.getStatus() != CSRStatus.PENDING) {
            throw new IllegalStateException("CSR has already been processed");
        }

        // Manual rejection by CA
        if (manualRejectionReason != null && !manualRejectionReason.isBlank()) {
            csr.setStatus(CSRStatus.REJECTED);
            csr.setRejectionReason(manualRejectionReason);
            csrRepository.save(csr);
            return csr;
        }

        // Load signing certificate
        Certificate signingCert = certificateRepository.findById(signingCertificateId)
                .orElseThrow(() -> new IllegalArgumentException("Signing certificate not found"));

        // Load keystore containing signing certificate
        Keystore keystore = keystoreRepository.findById(signingCert.getKeystore().getId())
                .orElseThrow(() -> new IllegalStateException("Keystore not found"));

        String decryptedPassword = cryptoService.decryptAES(keystore.getEncryptedPassword(), masterKey);
        KeyStore ks = KeyStore.getInstance("PKCS12");
        try (FileInputStream fis = new FileInputStream("certificates/keystore_" + keystore.getId() + ".p12")) {
            ks.load(fis, decryptedPassword.toCharArray());
        }

        // Load signing certificate private key
        PublicKey csrPublicKey = cryptoService.loadPublicKeyFromPem(csr.getPem()); // assumes helper method exists

        String alias = signingCert.getAlias();

        X509Certificate issuerCert = (X509Certificate) ks.getCertificate(alias);
        X500Name issuerName = X500Name.getInstance(issuerCert.getSubjectX500Principal().getEncoded());

        // Automatic validation
        String rejectionReason = validateCsr(csr, issuerCert, csrPublicKey);
        if (rejectionReason != null) {
            csr.setStatus(CSRStatus.REJECTED);
            csr.setRejectionReason(rejectionReason);
            csrRepository.save(csr);
            return csr;
        }

        // Build certificate
        BigInteger serial = BigInteger.valueOf(System.currentTimeMillis());
        Date notBefore = Date.from(csr.getCreatedAt().atZone(ZoneId.systemDefault()).toInstant());
        Date notAfter = Date.from(csr.getCreatedAt().plusDays(csr.getValidityDays())
                .atZone(ZoneId.systemDefault()).toInstant());

        X500Name subjectName = new X500Name(String.format("CN=%s,O=%s,EMAILADDRESS=%s",
                csr.getCommonName(), csr.getOrganization(), csr.getEmail()));

        X509v3CertificateBuilder certBuilder = new JcaX509v3CertificateBuilder(
                issuerName,
                serial,
                notBefore,
                notAfter,
                subjectName,
                csrPublicKey
        );

        // Apply extensions from CSR
        if (csr.getRequestedExtensionsJson() != null && !csr.getRequestedExtensionsJson().isBlank()) {
            Map<String, String> extMap = objectMapper.readValue(csr.getRequestedExtensionsJson(),
                    new TypeReference<Map<String, String>>() {});
            for (Map.Entry<String, String> e : extMap.entrySet()) {
                ASN1ObjectIdentifier oid = new ASN1ObjectIdentifier(e.getKey());
                byte[] value = Base64.getDecoder().decode(e.getValue());
                certBuilder.addExtension(oid, false, value); // non-critical by default
            }
        }

        PrivateKey issuerPrivateKey = (PrivateKey) ks.getKey(alias, decryptedPassword.toCharArray());

        // Sign certificate with issuer
        ContentSigner signer = new JcaContentSignerBuilder("SHA256withRSA").build(issuerPrivateKey);
        X509Certificate newCert = new JcaX509CertificateConverter().setProvider("BC")
                .getCertificate(certBuilder.build(signer));

        // Store as TrustedCertificateEntry (no private key)
        ks.setCertificateEntry(newCert.getSerialNumber().toString(), newCert);
        try (FileOutputStream fos = new FileOutputStream("certificates/keystore_" + keystore.getId() + ".p12")) {
            ks.store(fos, decryptedPassword.toCharArray());
        }

        //saveCertToDb(X509Certificate cert, User user, CertificateType type, Keystore keystore)
        User csrOwner = userRepository.findById(csr.getOwnerId())
                .orElseThrow(() -> new IllegalArgumentException("User not found", null));
        saveCertToDb(newCert, csrOwner, CertificateType.END_ENTITY, keystore);

        csr.setStatus(CSRStatus.SIGNED);
        csrRepository.save(csr);
        return csr;
    }

    private String validateCsr(CSR csr, X509Certificate issuerCert, PublicKey csrPublicKey) {
        // Check dates
        if (csr.getValidityDays() == null || csr.getValidityDays() <= 0) {
            return "Invalid validity period";
        }
        Date notBefore = Date.from(csr.getCreatedAt().atZone(ZoneId.systemDefault()).toInstant());
        Date notAfter = Date.from(csr.getCreatedAt().plusDays(csr.getValidityDays())
                .atZone(ZoneId.systemDefault()).toInstant());
        if (notAfter.after(issuerCert.getNotAfter()) || notBefore.before(issuerCert.getNotBefore())) {
            return "CSR validity period exceeds issuer certificate";
        }

        // Check mandatory fields
        if (csr.getCommonName() == null || csr.getCommonName().isBlank()) return "Missing CN";
        if (csr.getOrganization() == null || csr.getOrganization().isBlank()) return "Missing O";
        if (csr.getEmail() == null || csr.getEmail().isBlank()) return "Missing Email";

        // Check public key algorithm & size
        if ("RSA".equalsIgnoreCase(csrPublicKey.getAlgorithm()) &&
                ((java.security.interfaces.RSAPublicKey) csrPublicKey).getModulus().bitLength() < 2048) {
            return "RSA key too small";
        }
        if ("EC".equalsIgnoreCase(csrPublicKey.getAlgorithm()) &&
                ((java.security.interfaces.ECPublicKey) csrPublicKey).getParams().getCurve().getField().getFieldSize() < 256) {
            return "EC key too small";
        }

        return null; // valid
    }

    public List<CertificateDTO> getAllSignedCertByOwnerId(Long userId){
        User user = userRepository.findById(userId)
                .orElseThrow(() -> new IllegalArgumentException("User not found", null));

        if(user.getRole() == UserRole.BASIC) {
            throw new IllegalArgumentException("Basic users cannot view signed certificates", null);
        }
        List<CertificateDTO> certificateDTOS = certificateRepository.findAllByOwnerAndSigned(userId)
                .stream()
                .map(cert -> new CertificateDTO(cert, userId.equals(cert.getOwner().getId())))
                .toList();

        return certificateDTOS;
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

    public void issueCertificate(CertificateIssueDTO issue, Long issuerId) throws Exception {
        Certificate signingCertificate = certificateRepository.findById(issue.getIssuerCertificateId())
                .orElseThrow(() -> new RuntimeException("Certificate not found"));

        User subject = userRepository.findById(issue.getSubjectId())
                .orElseThrow(() -> new CertificateGenerationException("User not found", null));

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
        java.security.cert.Certificate[] issuerChain = ks.getCertificateChain(alias);

        if (issuerChain == null || issuerChain.length == 0) {
            throw new IllegalStateException("No certificate chain found in keystore for alias: " + alias);
        }

        BigInteger serial = BigInteger.valueOf(System.currentTimeMillis());
        KeyPair keyPair = cryptoService.generateRSAKeyPair();
        X500Name subjectInformation = buildSubject(issue);
        X509Certificate signingCert = (X509Certificate) ks.getCertificate(alias);
        X500Name issuerName = X500Name.getInstance(signingCert.getSubjectX500Principal().getEncoded());

        X509v3CertificateBuilder certificateBuilder = new JcaX509v3CertificateBuilder(
                issuerName,
                serial,
                Date.from(issue.getValidFrom().atZone(ZoneId.systemDefault()).toInstant()),
                Date.from(issue.getValidTo().atZone(ZoneId.systemDefault()).toInstant()),
                subjectInformation,
                keyPair.getPublic()
        );

        boolean isCA = subject.getRole().equals(UserRole.CA);
        certificateBuilder.addExtension(
                org.bouncycastle.asn1.x509.Extension.basicConstraints,
                true,
                new org.bouncycastle.asn1.x509.BasicConstraints(isCA) // CA = true
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


        java.security.cert.Certificate[] newChain = new java.security.cert.Certificate[issuerChain.length + 1];
        newChain[0] = newCert;
        System.arraycopy(issuerChain, 0, newChain, 1, issuerChain.length);

        ks.setKeyEntry(newCert.getSerialNumber().toString(), keyPair.getPrivate(),
                decryptedPassword.toCharArray(), newChain);

        try (FileOutputStream fos = new FileOutputStream("certificates/keystore_" + keystore.getId() + ".p12")) {
            ks.store(fos, decryptedPassword.toCharArray());
        }

        CertificateType certificateType = isCA ? CertificateType.INTERMEDIATE : CertificateType.END_ENTITY;
        saveCertToDb(newCert, subject, certificateType, keystore);
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
