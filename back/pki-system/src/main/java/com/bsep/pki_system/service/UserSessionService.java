package com.bsep.pki_system.service;

import com.bsep.pki_system.model.User;
import com.bsep.pki_system.model.UserSession;
import com.bsep.pki_system.repository.UserSessionRepository;
import org.springframework.stereotype.Service;

import java.time.LocalDateTime;
import java.util.List;
import java.util.Optional;

@Service
public class UserSessionService {

    private final UserSessionRepository sessionRepository;

    public UserSessionService(UserSessionRepository sessionRepository) {
        this.sessionRepository = sessionRepository;
    }

    public UserSession createSession(User user, String jti, String ipAddress, String userAgent, LocalDateTime expiresAt) {
        UserSession session = new UserSession(user, jti, ipAddress, userAgent, LocalDateTime.now(), expiresAt);
        return sessionRepository.save(session);
    }

    public void invalidateSession(Long userId, String jti) {
        UserSession session = sessionRepository.findByJti(jti);
        if (session != null && session.getUser().getId().equals(userId)) {
            session.setRevoked(true);
            sessionRepository.save(session);
        }
    }

    public List<UserSession> getSessionsByUserId(Long userId) {
        return sessionRepository.findByUserId(userId);
    }

    public Optional<UserSession> getSessionByJti(String jti) {
        return Optional.ofNullable(sessionRepository.findByJti(jti));
    }

    public boolean isSessionValid(String jti) {
        UserSession session = sessionRepository.findByJti(jti);
        if (session == null) return false;

        boolean notRevoked = !session.isRevoked();
        boolean notExpired = session.getExpiresAt() == null || session.getExpiresAt().isAfter(LocalDateTime.now());

        return notRevoked && notExpired;
    }

    public void updateLastActivity(String jti) {
        UserSession session = sessionRepository.findByJti(jti);
        if (session != null) {
            session.setLastActivity(LocalDateTime.now());
            sessionRepository.save(session);
        }
    }

    public List<UserSession> getActiveSessionsForUser(Long userId) {
        List<UserSession> sessions = this.getSessionsByUserId(userId);
        LocalDateTime now = LocalDateTime.now();

        return sessions.stream()
                .filter(s -> !s.isRevoked() && s.getExpiresAt().isAfter(now))
                .toList();
    }
}