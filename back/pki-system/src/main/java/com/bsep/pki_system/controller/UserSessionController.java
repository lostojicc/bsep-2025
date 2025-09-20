package com.bsep.pki_system.controller;

import com.bsep.pki_system.jwt.JwtService;
import com.bsep.pki_system.model.UserSession;
import com.bsep.pki_system.service.UserSessionService;
import jakarta.servlet.http.HttpServletRequest;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.*;

import java.util.List;
import java.util.Map;

@RestController
@RequestMapping("/session")
public class UserSessionController {

    private final UserSessionService sessionService;

    public UserSessionController(UserSessionService sessionService) {
        this.sessionService = sessionService;
    }

    @GetMapping
    public ResponseEntity<?> getActiveSessions(@RequestParam("userId") Long userId) {
        List<UserSession> activeSessions = sessionService.getActiveSessionsForUser(userId);
        return ResponseEntity.ok(activeSessions);
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
}
