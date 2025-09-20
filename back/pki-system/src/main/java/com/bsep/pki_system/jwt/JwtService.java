package com.bsep.pki_system.jwt;

import com.bsep.pki_system.model.User;
import com.bsep.pki_system.service.UserService;
import com.bsep.pki_system.service.UserSessionService;
import io.jsonwebtoken.Claims;
import io.jsonwebtoken.JwtException;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;
import io.jsonwebtoken.security.Keys;
import jakarta.servlet.http.HttpServletRequest;
import org.springframework.lang.NonNull;
import org.springframework.stereotype.Service;

import javax.crypto.SecretKey;
import java.nio.charset.StandardCharsets;
import java.security.Key;
import java.time.LocalDateTime;
import java.util.Date;
import java.util.UUID;


@Service
public class JwtService {

    private final String jwtSecret = "my-super-long-secret-key-that-is-at-least-32-bytes!";
    private final long jwtExpirationMs = 86400000; // 1 day
    private final UserSessionService sessionService;

    public JwtService(UserSessionService sessionService) {
        this.sessionService = sessionService;
    }

    public SecretKey getSigningKey() {
        return Keys.hmacShaKeyFor(jwtSecret.getBytes(StandardCharsets.UTF_8));
    }

    public String generateToken(User user, String ip, String userAgent) {
        String jti = UUID.randomUUID().toString();

        String token = Jwts.builder()
                .id(jti)
                .subject(user.getEmail())
                .claim("userId", user.getId())
                .claim("role", user.getRole().name())
                .issuedAt(new Date())
                .expiration(new Date(System.currentTimeMillis() + jwtExpirationMs))
                .signWith(getSigningKey())
                .compact();

        LocalDateTime expiresAt = LocalDateTime.now().plusSeconds(jwtExpirationMs / 1000);

        sessionService.createSession(user, jti, ip, userAgent, expiresAt);

        return token;
    }

    public boolean validateToken(String token) {
        try {
            Claims claims = getClaims(token);

            boolean notExpired = !claims.getExpiration().before(new Date());

            String jti = claims.getId();
            boolean sessionValid = sessionService.isSessionValid(jti);

            return notExpired && sessionValid;
        } catch (JwtException e) {
            return false;
        }
    }

    public Claims getClaims(String token) {
        return Jwts.parser()
                .verifyWith(getSigningKey())
                .build()
                .parseSignedClaims(token)
                .getPayload();
    }

    public Long getUserIdFromToken(String token) {
        Claims claims = getClaims(token);
        return claims.get("userId", Long.class);
    }

    public String getRoleFromToken(String token) {
        Claims claims = getClaims(token);
        return claims.get("role", String.class);
    }

    public String getJtiFromToken(String token) {
        Claims claims = getClaims(token);
        return claims.getId();
    }

    public static String extractTokenFromRequest(HttpServletRequest request) {
        String authHeader = request.getHeader("Authorization");
        if (authHeader == null || !authHeader.startsWith("Bearer ")) {
            return null;
        }
        return authHeader.substring(7);
    }
}