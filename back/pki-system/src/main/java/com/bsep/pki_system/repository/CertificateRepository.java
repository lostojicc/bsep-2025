package com.bsep.pki_system.repository;

import com.bsep.pki_system.model.Certificate;
import org.springframework.data.jpa.repository.JpaRepository;

public interface CertificateRepository extends JpaRepository<Certificate, Long> {
}
