package com.bsep.pki_system.controller;

import com.bsep.pki_system.dto.*;
import com.bsep.pki_system.jwt.JwtService;
import com.bsep.pki_system.model.User;
import com.bsep.pki_system.model.UserRole;
import com.bsep.pki_system.model.UserSession;
import com.bsep.pki_system.service.CaptchaService;
import com.bsep.pki_system.service.UserService;
import com.bsep.pki_system.service.UserSessionService;
import jakarta.servlet.http.HttpServletRequest;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.*;

import java.time.LocalDateTime;
import java.util.List;
import java.util.Map;

@RestController
@RequestMapping("/auth")
public class AuthController {

    private final UserService userService;
    private final JwtService jwtService;
    private final CaptchaService captchaService;
    private final UserSessionService sessionService;

    public AuthController(UserService userService, JwtService jwtService, CaptchaService captchaService, UserSessionService sessionService) {
        this.userService = userService;
        this.jwtService = jwtService;
        this.captchaService = captchaService;
        this.sessionService = sessionService;
    }

    @PostMapping("/register")
    public ResponseEntity<?> register(@RequestBody RegisterDTO request) {
        try {
            User savedUser = userService.registerUser(request);
            return ResponseEntity.ok("User registered with ID: " + savedUser.getId());
        } catch (IllegalArgumentException e) {
            return ResponseEntity
                    .badRequest()
                    .body(e.getMessage());
        } catch (Exception e) {
            return ResponseEntity
                    .status(HttpStatus.INTERNAL_SERVER_ERROR)
                    .body("An error occurred while registering the user");
        }
    }

    @PostMapping("/login")
    public ResponseEntity<?> login(@RequestBody LoginDTO request, HttpServletRequest httpRequest) {
        if (!captchaService.verifyToken(request.getRecaptchaToken())) {
            return ResponseEntity.badRequest().body("Captcha verification failed");
        }

        User user = userService.login(request.getEmail(), request.getPassword());
        if (user == null) {
            return ResponseEntity.badRequest().body("Invalid credentials");
        }

        if(!user.isActivated()){
            return ResponseEntity.badRequest().body("Account not activated!");
        }

        String ip = httpRequest.getRemoteAddr();
        String userAgent = httpRequest.getHeader("User-Agent");

        String token = jwtService.generateToken(user, ip , userAgent);

        return ResponseEntity.ok(new LoginResponseDTO(token,user.getId(),user.getEmail(),user.getRole().toString(), user.isCaPasswordChanged()));
    }

    @PostMapping("/recovery")
    public ResponseEntity<?> recovery(@RequestBody ForgotPasswordDTO request) {

        if (request.getEmail() == null || request.getEmail().isEmpty()) {
            return ResponseEntity.badRequest().body("Email is required");
        }
        try {
            userService.forgotPassword(request.getEmail());
            return ResponseEntity.ok("Password reset link has been sent to your email.");
        } catch (RuntimeException e) {
            return ResponseEntity.badRequest().body(e.getMessage());
        } catch (Exception e) {
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR).body("Something went wrong");
        }

    }
    @PostMapping("/reset-password")
    public ResponseEntity<?> resetPassword(@RequestBody ResetPasswordDTO request) {
        try {
            userService.resetPassword(request.getToken(), request.getNewPassword());
            return ResponseEntity.ok("Password has been reset successfully.");
        } catch (IllegalArgumentException e) {
            return ResponseEntity.badRequest().body(e.getMessage());
        } catch (Exception e) {
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR)
                    .body("Failed to reset password.");
        }
    }
    @GetMapping("/activate")
    public ResponseEntity<String> activateUser(@RequestParam("token") String token) {
        try {
            String result = userService.activateUser(token);
            return ResponseEntity.ok(result);
        } catch (IllegalArgumentException e) {
            return ResponseEntity.badRequest().body(e.getMessage());
        }
    }

    @PostMapping("/logout")
    public ResponseEntity<?> logout(HttpServletRequest request) {
        String token = JwtService.extractTokenFromRequest(request);
        if (token == null) {
            return ResponseEntity.badRequest().body("Missing or invalid Authorization header");
        }

        String jti = jwtService.getJtiFromToken(token);
        Long userId = jwtService.getUserIdFromToken(token);
        sessionService.invalidateSession(userId, jti);

        return ResponseEntity.ok("Logged out successfully");
    }

    @PostMapping("/registerCA")
    @PreAuthorize("hasRole('ADMIN')")
    public ResponseEntity<?> registerCA(@RequestBody RegisterDTO request) {
        try {
            User savedUser = userService.registerCA(request);
            return ResponseEntity.ok("CA registered with ID: " + savedUser.getId());
        } catch (IllegalArgumentException e) {
            return ResponseEntity
                    .badRequest()
                    .body(e.getMessage());
        } catch (Exception e) {
            return ResponseEntity
                    .status(HttpStatus.INTERNAL_SERVER_ERROR)
                    .body("An error occurred while registering ca user");
        }
    }


    @PostMapping("/change-password")
    @PreAuthorize("hasRole('CA')")
    public ResponseEntity<?> changePassword(@RequestBody ChangePasswordDTO dto, HttpServletRequest request) {
        try {
            String token = JwtService.extractTokenFromRequest(request);
            if (token == null) {
                return ResponseEntity.badRequest().body("Missing or invalid Authorization header");
            }
            Long userId = jwtService.getUserIdFromToken(token);
            userService.changeCAPassword(userId, dto.getNewPassword());
            return ResponseEntity.ok("Password changed successfully");
        } catch (IllegalArgumentException | IllegalStateException e) {
            return ResponseEntity.badRequest().body(e.getMessage());
        } catch (Exception e) {
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR)
                    .body("An error occurred while changing the password");
        }
    }
}