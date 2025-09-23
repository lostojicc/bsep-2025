package com.bsep.pki_system.repository;

import com.bsep.pki_system.model.User;
import org.springframework.data.jpa.repository.JpaRepository;

import java.util.Optional;

public interface UserRepository extends JpaRepository<User, Long> {
    Optional<User> findByEmail(String email);

    Optional<User> findByActivationToken(String token);

    boolean existsByEmail(String email);

}