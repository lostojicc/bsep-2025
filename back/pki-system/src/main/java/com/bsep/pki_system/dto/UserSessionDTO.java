package com.bsep.pki_system.dto;

import lombok.AllArgsConstructor;
import lombok.Getter;
import lombok.Setter;

import java.time.LocalDateTime;

@Getter
@Setter
@AllArgsConstructor
public class UserSessionDTO {
    private String ipAddress;
    private String userAgent;
    private LocalDateTime lastActivity;
    private LocalDateTime createdAt;
    private LocalDateTime expiresAt;
    private String jti;
    private boolean currentSession;
}