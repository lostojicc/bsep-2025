package com.bsep.pki_system.repository;

import com.bsep.pki_system.model.UserSession;
import org.springframework.data.jpa.repository.JpaRepository;

import java.util.List;

public interface UserSessionRepository extends JpaRepository<UserSession, Long> {
    List<UserSession> findByUserId(Long userId);

    UserSession findByJti(String jti);
}
