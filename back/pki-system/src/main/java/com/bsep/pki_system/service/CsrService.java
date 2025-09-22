package com.bsep.pki_system.service;

import com.bsep.pki_system.model.CSR;
import com.bsep.pki_system.repository.CsrRepository;
import com.bsep.pki_system.repository.UserRepository;
import jakarta.transaction.Transactional;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.x500.RDN;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x500.style.BCStyle;
import org.bouncycastle.openssl.PEMParser;
import org.bouncycastle.openssl.jcajce.JcaPEMKeyConverter;
import org.bouncycastle.operator.ContentVerifierProvider;
import org.bouncycastle.operator.jcajce.JcaContentVerifierProviderBuilder;
import org.bouncycastle.pkcs.PKCS10CertificationRequest;
import org.bouncycastle.util.encoders.Hex;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;
import org.springframework.web.multipart.MultipartFile;

import java.io.StringReader;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.PublicKey;
import java.security.interfaces.ECPublicKey;
import java.security.interfaces.RSAPublicKey;
import java.time.LocalDateTime;


@Service
public class CsrService {

    private final CsrRepository csrRepository;
    private  final UserRepository userRepository;
    private final Logger logger = LoggerFactory.getLogger(CsrService.class);


    @Autowired
    public CsrService(CsrRepository csrRepository, UserRepository userRepository) {
        this.csrRepository = csrRepository;
        this.userRepository = userRepository;
    }

    @Transactional
    public CSR handleUpload(MultipartFile file,
                            String caName,
                            int validityDays,
                            String userEmails,
                            String clientIp) throws Exception {

        if (file == null || file.isEmpty()) {
            throw new IllegalArgumentException("CSR file is required");
        }

        String pem = new String(file.getBytes(), StandardCharsets.UTF_8);
        if (!pem.contains("-----BEGIN CERTIFICATE REQUEST-----")) {
            throw new IllegalArgumentException("File is not a valid PEM CSR");
        }

        // Parsiranje CSRa
        PKCS10CertificationRequest csr;
        try (PEMParser pemParser = new PEMParser(new StringReader(pem))) {
            Object parsed = pemParser.readObject();
            if (!(parsed instanceof PKCS10CertificationRequest)) {
                throw new IllegalArgumentException("Invalid CSR format");
            }
            csr = (PKCS10CertificationRequest) parsed;
        }

        ContentVerifierProvider verifier = new JcaContentVerifierProviderBuilder()
                .setProvider("BC")
                .build(csr.getSubjectPublicKeyInfo());

        if (!csr.isSignatureValid(verifier)) {
            throw new IllegalArgumentException("CSR signature is invalid");
        }

        X500Name subject = csr.getSubject();
        String cn = getRdnValue(subject, BCStyle.CN);
        String org = getRdnValue(subject, BCStyle.O);
        String email = getRdnValue(subject, BCStyle.E);

        PublicKey pubKey = new JcaPEMKeyConverter().setProvider("BC").getPublicKey(csr.getSubjectPublicKeyInfo());
        String alg = pubKey.getAlgorithm();
        int keySize = getKeySize(pubKey);

        if ("RSA".equalsIgnoreCase(alg) && keySize < 2048) {
            throw new IllegalArgumentException("RSA key too small, minimum 2048 bits required");
        }

        byte[] derEncoded = csr.getEncoded();
        MessageDigest md = MessageDigest.getInstance("SHA-256");
        String fingerprint = Hex.toHexString(md.digest(derEncoded));

        Long ownerId = userRepository.findByEmail(userEmails)
                .orElseThrow(() -> new IllegalArgumentException("User not found"))
                .getId();

        CSR entity = new CSR();
        entity.setOwnerId(ownerId);
        entity.setCaName(caName);
        entity.setValidityDays(validityDays);
        entity.setCommonName(cn);
        entity.setOrganization(org);
        entity.setEmail(email);
        entity.setPublicKeyAlg(alg);
        entity.setPublicKeySize(keySize);
        entity.setCsrFingerprint(fingerprint);
        entity.setSignatureValid(true);
        entity.setPem(pem);
        entity.setStatus("PENDING");
        entity.setCreatedAt(LocalDateTime.now());

        CSR saved = csrRepository.save(entity);

        logger.info("CSR uploaded: user={}, ip={}, fingerprint={}, caName={}, validityDays={}",
                userEmails, clientIp, fingerprint, caName, validityDays);

        return saved;
    }

    private String getRdnValue(X500Name name, ASN1ObjectIdentifier id) {
        RDN[] rdns = name.getRDNs(id);
        return rdns.length > 0 ? rdns[0].getFirst().getValue().toString() : null;
    }

    private int getKeySize(PublicKey pubKey) {
        if (pubKey instanceof RSAPublicKey) {
            return ((RSAPublicKey) pubKey).getModulus().bitLength();
        } else if (pubKey instanceof ECPublicKey) {
            return ((ECPublicKey) pubKey).getParams().getCurve().getField().getFieldSize();
        }
        return -1; // nepoznato
    }
}
