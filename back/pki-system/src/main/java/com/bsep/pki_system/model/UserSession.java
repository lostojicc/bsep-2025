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
@Table(name = "user_session")
public class UserSession {
    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @ManyToOne(fetch = FetchType.LAZY)
    @JoinColumn(name = "user_id", nullable = false)
    private User user;

    // JWT identifier (jti claim)
    @Column(name = "jti", nullable = false, unique = true)
    private String jti;

    @Column(name = "ip_address", length = 45)
    private String ipAddress;

    // User-Agent / browser info
    @Column(name = "user_agent", length = 255)
    private String userAgent;

    @Column(name = "created_at", nullable = false)
    private LocalDateTime createdAt;

    @Column(name = "last_activity")
    private LocalDateTime lastActivity;

    @Column(name = "expires_at")
    private LocalDateTime expiresAt;

    @Column(name = "revoked", nullable = false)
    private boolean revoked;

    public UserSession(User user, String jti, String ipAddress, String userAgent, LocalDateTime createdAt, LocalDateTime expiresAt) {
        this.user = user;
        this.jti = jti;
        this.ipAddress = ipAddress;
        this.userAgent = userAgent;
        this.createdAt = createdAt;
        this.lastActivity = createdAt;
        this.expiresAt = expiresAt;
        this.revoked = false;
    }
}
