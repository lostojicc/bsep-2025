package com.bsep.pki_system.service;

import com.bsep.pki_system.model.CSR;
import com.bsep.pki_system.model.CSRStatus;
import com.bsep.pki_system.model.User;
import com.bsep.pki_system.model.UserRole;
import com.bsep.pki_system.repository.CsrRepository;
import com.bsep.pki_system.repository.UserRepository;
import com.fasterxml.jackson.databind.ObjectMapper;
import jakarta.transaction.Transactional;
import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.ASN1Set;
import org.bouncycastle.asn1.pkcs.Attribute;
import org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers;
import org.bouncycastle.asn1.x509.*;
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
import org.springframework.stereotype.Service;
import org.springframework.web.multipart.MultipartFile;

import java.io.StringReader;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.PublicKey;
import java.security.interfaces.ECPublicKey;
import java.security.interfaces.RSAPublicKey;
import java.time.LocalDateTime;
import java.util.*;
import java.util.stream.Collectors;

@Service
public class CsrService {

    private final CsrRepository csrRepository;
    private final UserRepository userRepository;
    private final Logger logger = LoggerFactory.getLogger(CsrService.class);
    private final ObjectMapper objectMapper = new ObjectMapper();

    public CsrService(CsrRepository csrRepository, UserRepository userRepository) {
        this.csrRepository = csrRepository;
        this.userRepository = userRepository;
    }

    @Transactional
    public CSR handleUpload(MultipartFile file,
                            Long caId,
                            int validityDays,
                            String userEmail,
                            String clientIp) throws Exception {

        if (file == null || file.isEmpty()) {
            throw new IllegalArgumentException("CSR file is required");
        }

        User ca = userRepository.findById(caId)
                .filter(u -> u.getRole() == UserRole.CA)
                .orElseThrow(() -> new IllegalArgumentException("CA user not found"));

        String pem = new String(file.getBytes(), StandardCharsets.UTF_8);
        if (!pem.contains("-----BEGIN CERTIFICATE REQUEST-----")) {
            throw new IllegalArgumentException("File is not a valid PEM CSR");
        }

        // Parse CSR
        PKCS10CertificationRequest csrHolder;
        try (PEMParser pemParser = new PEMParser(new StringReader(pem))) {
            Object parsed = pemParser.readObject();
            if (!(parsed instanceof PKCS10CertificationRequest)) {
                throw new IllegalArgumentException("Invalid CSR format");
            }
            csrHolder = (PKCS10CertificationRequest) parsed;
        }

        ContentVerifierProvider verifier = new JcaContentVerifierProviderBuilder()
                .setProvider("BC")
                .build(csrHolder.getSubjectPublicKeyInfo());

        if (!csrHolder.isSignatureValid(verifier)) {
            throw new IllegalArgumentException("CSR signature is invalid");
        }

        // Extract subject data
        X500Name subject = csrHolder.getSubject();
        String cn = getRdnValue(subject, BCStyle.CN);
        String org = getRdnValue(subject, BCStyle.O);
        String email = getRdnValue(subject, BCStyle.E);

        // Extract public key
        PublicKey pubKey = new JcaPEMKeyConverter().setProvider("BC").getPublicKey(csrHolder.getSubjectPublicKeyInfo());
        String alg = pubKey.getAlgorithm();
        int keySize = getKeySize(pubKey);

        if ("RSA".equalsIgnoreCase(alg) && keySize < 2048) {
            throw new IllegalArgumentException("RSA key too small, minimum 2048 bits required");
        }

        // Compute fingerprint
        byte[] derEncoded = csrHolder.getEncoded();
        MessageDigest md = MessageDigest.getInstance("SHA-256");
        String fingerprint = Hex.toHexString(md.digest(derEncoded));

        // Get owner ID
        Long ownerId = userRepository.findByEmail(userEmail)
                .orElseThrow(() -> new IllegalArgumentException("User not found"))
                .getId();

        // Extract requested extensions
        Extensions extensions = null;
        Attribute[] attrs = csrHolder.getAttributes(PKCSObjectIdentifiers.pkcs_9_at_extensionRequest);
        if (attrs != null && attrs.length > 0) {
            ASN1Set attrValues = attrs[0].getAttrValues();
            if (attrValues.size() > 0) {
                extensions = Extensions.getInstance(attrValues.getObjectAt(0));
            }
        }

        String extensionsJson = null;
        if (extensions != null) {
            Map<String, Object> extMap = new HashMap<>();
            for (ASN1ObjectIdentifier oid : extensions.getExtensionOIDs()) {
                ASN1Primitive val = extensions.getExtension(oid).getParsedValue().toASN1Primitive();
                extMap.put(oid.getId(), val.toString());
            }
            extensionsJson = objectMapper.writeValueAsString(extMap);
        }



        // Save CSR
        CSR entity = new CSR();
        entity.setOwnerId(ownerId);
        entity.setCaId(caId);
        entity.setValidityDays(validityDays);
        entity.setCommonName(cn);
        entity.setOrganization(org);
        entity.setEmail(email);
        entity.setPublicKeyAlg(alg);
        entity.setPublicKeySize(keySize);
        entity.setCsrFingerprint(fingerprint);
        entity.setSignatureValid(true);
        entity.setPem(pem);
        entity.setStatus(CSRStatus.PENDING);
        entity.setCreatedAt(LocalDateTime.now());
        entity.setRequestedExtensionsJson(extensionsJson);
        entity.setRejectionReason(null);

        CSR saved = csrRepository.save(entity);

        logger.info("CSR uploaded: user={}, ip={}, fingerprint={}, caId={}, validityDays={}",
                userEmail, clientIp, fingerprint, caId, validityDays);

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
        return -1;
    }
}
