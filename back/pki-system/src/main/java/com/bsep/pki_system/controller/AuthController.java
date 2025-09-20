package com.bsep.pki_system.controller;

import com.bsep.pki_system.dto.LoginDTO;
import com.bsep.pki_system.dto.LoginResponseDTO;
import com.bsep.pki_system.dto.RegisterDTO;
import com.bsep.pki_system.jwt.JwtService;
import com.bsep.pki_system.model.User;
import com.bsep.pki_system.model.UserRole;
import com.bsep.pki_system.service.CaptchaService;
import com.bsep.pki_system.service.UserService;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import java.time.LocalDateTime;
import java.util.Map;

@RestController
@RequestMapping("/auth")
public class AuthController {

    private final UserService userService;
    private final JwtService jwtService;
    private final CaptchaService captchaService;

    public AuthController(UserService userService, JwtService jwtService, CaptchaService captchaService) {
        this.userService = userService;
        this.jwtService = jwtService;
        this.captchaService = captchaService;
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
    public ResponseEntity<?> login(@RequestBody LoginDTO request) {
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

        String token = jwtService.generateToken(user);

        return ResponseEntity.ok(new LoginResponseDTO(token,user.getId(),user.getEmail(),user.getRole().toString()));
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
}