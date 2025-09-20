package com.bsep.pki_system.controller;

import com.bsep.pki_system.dto.UserSessionDTO;
import com.bsep.pki_system.jwt.JwtService;
import com.bsep.pki_system.model.UserSession;
import com.bsep.pki_system.service.UserSessionService;
import jakarta.servlet.http.HttpServletRequest;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.*;

import java.net.Inet6Address;
import java.net.InetAddress;
import java.util.List;
import java.util.Map;

@RestController
@RequestMapping("/session")
public class UserSessionController {

    private final UserSessionService sessionService;
    private final JwtService jwtService;

    public UserSessionController(UserSessionService sessionService,  JwtService jwtService) {
        this.sessionService = sessionService;
        this.jwtService = jwtService;
    }

    @GetMapping
    public ResponseEntity<?> getActiveSessions(@RequestParam("userId") Long userId, HttpServletRequest request) {
        String token = JwtService.extractTokenFromRequest(request);
        String jti = jwtService.getJtiFromToken(token);

        List<UserSession> activeSessions = sessionService.getActiveSessionsForUser(userId);

        List<UserSessionDTO> sessionDTOs = activeSessions.stream()
                .map(session -> new UserSessionDTO(
                        normalizeIp(session.getIpAddress()),
                        session.getUserAgent(),
                        session.getLastActivity(),
                        session.getCreatedAt(),
                        session.getExpiresAt(),
                        session.getJti(),
                        session.getJti().equals(jti)
                ))
                .toList();

        return ResponseEntity.ok(sessionDTOs);
    }

    @PostMapping("/invalidate")
    public ResponseEntity<?> invalidateSession(@RequestBody Map<String, String> requestBody) {
        try {
            Long userId = Long.parseLong(requestBody.get("userId"));
            String jti = requestBody.get("jti");

            if (jti == null) {
                return ResponseEntity.badRequest().body("userId and jti are required");
            }

            sessionService.invalidateSession(userId, jti);
            return ResponseEntity.ok("Session invalidated successfully");
        } catch (NumberFormatException e) {
            return ResponseEntity.badRequest().body("Invalid userId format");
        }
    }

    private String normalizeIp(String ip) {
        if ("0:0:0:0:0:0:0:1".equals(ip) || "::1".equals(ip)) {
            return "127.0.0.1";
        }

        try {
            InetAddress inetAddress = InetAddress.getByName(ip);
            // If it's an IPv4-mapped IPv6 address, return the IPv4 part
            if (inetAddress instanceof Inet6Address inet6) {
                if (inet6.isIPv4CompatibleAddress()) {
                    byte[] addr = inet6.getAddress();
                    return String.format("%d.%d.%d.%d",
                            addr[12] & 0xff,
                            addr[13] & 0xff,
                            addr[14] & 0xff,
                            addr[15] & 0xff);
                }
            }
        } catch (Exception ignored) {}

        return ip;
    }
}
