package com.bsep.pki_system.repository;

import com.bsep.pki_system.model.Keystore;
import org.springframework.data.jpa.repository.JpaRepository;

public interface KeystoreRepository extends JpaRepository<Keystore, Long> {
}
