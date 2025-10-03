package com.bsep.pki_system.model;

import jakarta.persistence.*;
import java.time.LocalDateTime;

@Entity
@Table(name="csr_request")
public class CSR {

    @Id
    @GeneratedValue
    private Long id;

    @Column(name = "owner_id", nullable = false)
    private Long ownerId;

    @Column(name = "ca_id")
    private Long caId;

    private Integer validityDays;

    private String commonName; // iz CSR subjecta npr. www.ftn.com
    private String organization;
    private String email;

    private String publicKeyAlg; // RSA, EC npr
    private Integer publicKeySize;

    private String csrFingerprint; // obično SHA-256

    private boolean signatureValid;

    @Lob
    private String pem;

    @Enumerated(EnumType.STRING)
    private CSRStatus status;

    private LocalDateTime createdAt;

    // New: serialized CSR extensions (KeyUsage, EKU, SANs, etc.)
    @Lob
    @Column(name = "requested_extensions", columnDefinition = "TEXT")
    private String requestedExtensionsJson;

    @Column(name = "rejection_reason")
    private String rejectionReason;

    // === Getters & Setters ===

    public Long getId() {
        return id;
    }

    public String getRejectionReason() {
        return rejectionReason;
    }

    public void setRejectionReason(String rejectionReason) {
        this.rejectionReason = rejectionReason;
    }

    public void setId(Long id) {
        this.id = id;
    }

    public Long getOwnerId() {
        return ownerId;
    }

    public void setOwnerId(Long ownerId) {
        this.ownerId = ownerId;
    }

    public Long getCaId() {
        return caId;
    }

    public void setCaId(Long caId) {
        this.caId = caId;
    }

    public Integer getValidityDays() {
        return validityDays;
    }

    public void setValidityDays(Integer validityDays) {
        this.validityDays = validityDays;
    }

    public String getCommonName() {
        return commonName;
    }

    public void setCommonName(String commonName) {
        this.commonName = commonName;
    }

    public String getOrganization() {
        return organization;
    }

    public void setOrganization(String organization) {
        this.organization = organization;
    }

    public String getEmail() {
        return email;
    }

    public void setEmail(String email) {
        this.email = email;
    }

    public String getPublicKeyAlg() {
        return publicKeyAlg;
    }

    public void setPublicKeyAlg(String publicKeyAlg) {
        this.publicKeyAlg = publicKeyAlg;
    }

    public Integer getPublicKeySize() {
        return publicKeySize;
    }

    public void setPublicKeySize(Integer publicKeySize) {
        this.publicKeySize = publicKeySize;
    }

    public String getCsrFingerprint() {
        return csrFingerprint;
    }

    public void setCsrFingerprint(String csrFingerprint) {
        this.csrFingerprint = csrFingerprint;
    }

    public boolean isSignatureValid() {
        return signatureValid;
    }

    public void setSignatureValid(boolean signatureValid) {
        this.signatureValid = signatureValid;
    }

    public String getPem() {
        return pem;
    }

    public void setPem(String pem) {
        this.pem = pem;
    }

    public CSRStatus getStatus() {
        return status;
    }

    public void setStatus(CSRStatus status) {
        this.status = status;
    }

    public LocalDateTime getCreatedAt() {
        return createdAt;
    }

    public void setCreatedAt(LocalDateTime createdAt) {
        this.createdAt = createdAt;
    }

    public String getRequestedExtensionsJson() {
        return requestedExtensionsJson;
    }

    public void setRequestedExtensionsJson(String requestedExtensionsJson) {
        this.requestedExtensionsJson = requestedExtensionsJson;
    }
}
