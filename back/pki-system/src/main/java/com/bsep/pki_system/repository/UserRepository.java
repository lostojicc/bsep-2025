package com.bsep.pki_system.repository;

import com.bsep.pki_system.dto.CaUserDTO;
import com.bsep.pki_system.model.User;
import com.bsep.pki_system.model.UserRole;
import org.springframework.data.jpa.repository.JpaRepository;

import java.util.List;
import java.util.Optional;

public interface UserRepository extends JpaRepository<User, Long> {
    Optional<User> findByEmail(String email);

    Optional<User> findByActivationToken(String token);

    boolean existsByEmail(String email);

    List<User> findByRole(UserRole role);
}