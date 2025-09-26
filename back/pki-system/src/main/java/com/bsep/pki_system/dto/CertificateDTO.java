package com.bsep.pki_system.dto;

import com.bsep.pki_system.model.Certificate;
import com.bsep.pki_system.model.CertificateStatus;
import com.bsep.pki_system.model.CertificateType;
import com.bsep.pki_system.model.User;
import jakarta.persistence.*;
import lombok.AllArgsConstructor;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;

import java.time.LocalDateTime;

@Getter
@Setter
@AllArgsConstructor
@NoArgsConstructor
public class CertificateDTO {
    private Long id;

    private Long ownerId;

    private CertificateType certificateType;

    private String alias;

    private String serialNumber;

    private String issuerSerialNumber;

    private String subject;

    private LocalDateTime validFrom;

    private LocalDateTime validTo;

    private boolean isRevoked;

    private boolean canRevoke;

    private Long keystoreId;

    public CertificateDTO(Certificate certificate, boolean canRevoke) {
        this.id = certificate.getId();
        this.ownerId = certificate.getOwner() != null ? certificate.getOwner().getId() : null;
        this.certificateType = certificate.getType();
        this.alias = certificate.getAlias();
        this.serialNumber = certificate.getSerialNumber();
        this.issuerSerialNumber = certificate.getIssuerSerialNumber();
        this.subject = certificate.getSubject();
        this.validFrom = certificate.getValidFrom();
        this.validTo = certificate.getValidTo();
        this.isRevoked = certificate.getStatus() == CertificateStatus.REVOKED;
        this.canRevoke = canRevoke;
        this.keystoreId = certificate.getKeystore().getId();
    }
}
