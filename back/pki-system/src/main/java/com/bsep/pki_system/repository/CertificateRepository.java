package com.bsep.pki_system.repository;

import com.bsep.pki_system.model.Certificate;
import org.springframework.data.jpa.repository.JpaRepository;

import java.util.Optional;

public interface CertificateRepository extends JpaRepository<Certificate, Long> {
    Optional<Certificate> findCertificateByAlias(String alias);
}
