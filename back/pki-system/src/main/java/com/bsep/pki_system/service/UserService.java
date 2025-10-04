package com.bsep.pki_system.service;

import com.bsep.pki_system.dto.CaUserDTO;
import com.bsep.pki_system.dto.RegisterDTO;
import com.bsep.pki_system.model.PasswordResetToken;
import com.bsep.pki_system.model.User;
import com.bsep.pki_system.model.UserRole;
import com.bsep.pki_system.repository.PasswordResetTokenRepository;
import com.bsep.pki_system.repository.UserRepository;
import jakarta.transaction.Transactional;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.time.LocalDateTime;
import java.util.List;
import java.util.UUID;

@Service
public class UserService {
    private final UserRepository userRepository;
    private final PasswordResetTokenRepository tokenRepository;
    private final PasswordEncoder passwordEncoder;
    private final EmailSenderService emailSender;
    private final CryptoService cryptoService;

    public UserService(UserRepository userRepository, PasswordEncoder passwordEncoder, EmailSenderService emailSender,
                       PasswordResetTokenRepository tokenRepository, CryptoService cryptoService) {
        this.userRepository = userRepository;
        this.passwordEncoder = passwordEncoder;
        this.emailSender = emailSender;
        this.tokenRepository = tokenRepository;
        this.cryptoService = cryptoService;
    }

    public User registerUser(RegisterDTO request) {
        if (userRepository.existsByEmail(request.getEmail())) {
            throw new IllegalArgumentException("Email is already registered");
        }

        User user = new User();
        user.setName(request.getName());
        user.setSurname(request.getSurname());
        user.setEmail(request.getEmail());
        user.setPassword(passwordEncoder.encode(request.getPassword()));
        user.setOrganization(request.getOrganization());
        user.setRole(UserRole.BASIC);
        user.setActivated(false);
        user.setCaPasswordChanged(true);

        String token = UUID.randomUUID().toString();
        user.setActivationToken(token);
        user.setActivationTokenExpiry(LocalDateTime.now().plusHours(24));

        String activationLink = "http://localhost:8080/auth/activate?token=" + token;
        emailSender.sendActivationEmail(user.getEmail(), activationLink, "Activate account");

        return userRepository.save(user);
    }

    public User login(String email, String rawPassword) {
        return userRepository.findByEmail(email)
                .filter(user -> passwordEncoder.matches(rawPassword, user.getPassword()))
                .orElse(null);
    }

    @Transactional
    public String activateUser(String token) {
        User user = userRepository.findByActivationToken(token)
                .orElseThrow(() -> new IllegalArgumentException("Invalid activation token"));

        if (user.isActivated()) {
            return "User has already been activated";
        }

        if (user.getActivationTokenExpiry().isBefore(LocalDateTime.now())) {
            throw new IllegalArgumentException("Activation token has expired");
        }

        user.setActivated(true);
        user.setActivationToken(null);
        user.setActivationTokenExpiry(null);

        userRepository.save(user);

        return "User has been activated successfully";
    }

    public User registerCA(RegisterDTO request) {
        if (userRepository.existsByEmail(request.getEmail())) {
            throw new IllegalArgumentException("Email is already registered");
        }

        User user = new User();
        user.setName(request.getName());
        user.setSurname(request.getSurname());
        user.setEmail(request.getEmail());
        user.setOrganization(request.getOrganization());
        user.setRole(UserRole.CA);

        user.setActivated(true);
        user.setActivationToken(null);
        user.setActivationTokenExpiry(null);

        user.setCaPasswordChanged(false);

        String tempPassword = UUID.randomUUID().toString().substring(0, 12);
        user.setPassword(passwordEncoder.encode(tempPassword));

        emailSender.sendTemporaryPasswordEmail(user.getEmail(), tempPassword);

        return userRepository.save(user);
    }

    public void changeCAPassword(Long userId, String newPassword) {
        User user = userRepository.findById(userId)
                .orElseThrow(() -> new IllegalArgumentException("User not found"));

        if (!user.getRole().equals(UserRole.CA)) {
            throw new IllegalArgumentException("Only CA users can change CA password");
        }

        if (user.isCaPasswordChanged()) {
            throw new IllegalStateException("CA password has already been changed");
        }

        user.setPassword(passwordEncoder.encode(newPassword));

        user.setCaPasswordChanged(true);

        userRepository.save(user);
    }

        public void forgotPassword(String email) {
            User user = userRepository.findByEmail(email)
                    .orElseThrow(() -> new IllegalArgumentException("No account registered with this email"));

            try {
                String rawToken = UUID.randomUUID().toString();

                MessageDigest digest = MessageDigest.getInstance("SHA-256");
                byte[] hashBytes = digest.digest(rawToken.getBytes(StandardCharsets.UTF_8));
                StringBuilder sb = new StringBuilder();
                for (byte b : hashBytes) sb.append(String.format("%02x", b));
                String hashedToken = sb.toString();

                PasswordResetToken resetToken = new PasswordResetToken(
                        hashedToken,
                        user,
                        LocalDateTime.now().plusMinutes(15) // token valid for 15 min
                );
                tokenRepository.save(resetToken);

                String resetLink = "http://localhost:5173/reset-password?token=" + rawToken;
                emailSender.sendResetPasswordEmail(user.getEmail(), resetLink);

            } catch (Exception e) {
                throw new RuntimeException("Failed to generate reset token");
            }
        }

    @Transactional
    public void resetPassword(String token, String newPassword) {
        try {
            // Hash the incoming token (SHA-256)
            MessageDigest digest = MessageDigest.getInstance("SHA-256");
            byte[] hashBytes = digest.digest(token.getBytes(StandardCharsets.UTF_8));
            StringBuilder sb = new StringBuilder();
            for (byte b : hashBytes) sb.append(String.format("%02x", b));
            String hashedToken = sb.toString();

            // Find token in DB
            PasswordResetToken resetToken = tokenRepository.findByTokenAndUsedFalse(hashedToken)
                    .orElseThrow(() -> new IllegalArgumentException("Invalid or expired reset token"));

            if (resetToken.getExpiresAt().isBefore(LocalDateTime.now())) {
                throw new IllegalArgumentException("Reset token has expired");
            }

            User user = resetToken.getUser();
            user.setPassword(passwordEncoder.encode(newPassword));
            userRepository.save(user);

            resetToken.setUsed(true);
            tokenRepository.save(resetToken);

        } catch (NoSuchAlgorithmException e) {
            throw new RuntimeException("Failed to reset password");
        }
    }

    public List<CaUserDTO> getAllCAs() {
        return userRepository.findByRole(UserRole.CA)
                .stream()
                .map(user -> new CaUserDTO(
                        user.getId(),
                        user.getName(),
                        user.getSurname(),
                        user.getEmail()
                ))
                .toList();

    }

}
