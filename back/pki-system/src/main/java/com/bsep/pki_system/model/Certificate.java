package com.bsep.pki_system.model;

import jakarta.persistence.*;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;

import java.time.LocalDateTime;

@Entity
@Getter
@Setter
@NoArgsConstructor
@Table(name = "certificate")
public class Certificate {
    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    // Vlasnik cert
    @ManyToOne(fetch = FetchType.LAZY)
    @JoinColumn(
            name = "user_id",
            foreignKey = @ForeignKey(name = "fk_certificate_user")
    )
    private User owner;

    // Alias iz keystore
    @Column(unique = true, nullable = false)
    private String alias;

    // Serijski
    @Column(unique = true, nullable = false)
    private String serialNumber;

    // Serijski broj vlasnika, null ako je root
    @Column(nullable = true)
    private String issuerSerialNumber;

    // Subject info (CN, O, etc.)
    private String subject;

    // Issuer info (CN, O, etc.)
    private String issuer;

    // Validnost
    private LocalDateTime validFrom;
    private LocalDateTime validTo;

    // Status (ACTIVE, REVOKED, EXPIRED)
    @Enumerated(EnumType.STRING)
    private CertificateStatus status = CertificateStatus.ACTIVE;

    // Type (ROOT, INTERMEDIATE, END_ENTITY)
    @Enumerated(EnumType.STRING)
    private CertificateType type;

    // Za povlacenje cert
    private LocalDateTime revocationDate;
    private String revocationReason;

    // da znamo uvek u kom keystoru stoji
    @ManyToOne(fetch = FetchType.LAZY)
    @JoinColumn(name = "keystore_id",
            foreignKey = @ForeignKey(name = "fk_certificate_keystore"))
    private Keystore keystore;
}
