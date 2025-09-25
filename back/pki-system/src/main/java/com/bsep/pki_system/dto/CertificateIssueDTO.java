package com.bsep.pki_system.dto;

import com.bsep.pki_system.model.KeyUsageType;
import lombok.Getter;
import lombok.Setter;

import java.time.LocalDateTime;
import java.util.List;

@Getter
@Setter
public class CertificateIssueDTO {

    private Long subjectId;
    private Long issuerCertificateId;
    // Subject information
    private String commonName;
    private String organization;
    private String organizationalUnit;
    private String country;
    private String state;
    private String locality;
    private String email;

    // Validity period
    private LocalDateTime validFrom;
    private LocalDateTime validTo;

    // Extensions: key usages (flexible for future)
    private List<KeyUsageType> keyUsages;
}