package com.bsep.pki_system.repository;

import com.bsep.pki_system.model.CSR;
import org.springframework.data.jpa.repository.JpaRepository;

import java.util.Optional;

public interface CsrRepository extends JpaRepository<CSR, Long> {
    Optional<CSR> findByCsrFingerprint(String fingerprint);

}
