package com.bsep.pki_system.repository;

import com.bsep.pki_system.model.Certificate;
import com.bsep.pki_system.model.Keystore;
import com.bsep.pki_system.model.User;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;

import java.util.List;
import java.util.Optional;

public interface CertificateRepository extends JpaRepository<Certificate, Long> {
    Optional<Certificate> findCertificateByAlias(String alias);

    List<Certificate> findAllByOwnerOrderById(User adminUser);


    // query koji vraca sve sert iz heijerarhije koje su potpisane, za tog ownera
    // skup query
    @Query(value = """
        WITH RECURSIVE cert_tree AS (
            SELECT c.*
            FROM certificate c
            WHERE c.user_id = :ownerId
            
            UNION ALL
            
            SELECT child.*
            FROM certificate child
            INNER JOIN cert_tree parent 
                ON child.issuer_serial_number = parent.serial_number
        )
        SELECT * FROM cert_tree
        """, nativeQuery = true)
    List<Certificate> findAllByOwnerAndSigned(@Param("ownerId") Long ownerId);

    List<Certificate> findAllByKeystoreOrderByType(Keystore keystore);
}
