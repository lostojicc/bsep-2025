package com.bsep.pki_system.service;

import com.bsep.pki_system.dto.RegisterDTO;
import com.bsep.pki_system.model.User;
import com.bsep.pki_system.model.UserRole;
import com.bsep.pki_system.repository.UserRepository;
import jakarta.transaction.Transactional;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

import java.time.LocalDateTime;
import java.util.UUID;

@Service
public class UserService {
    private final UserRepository userRepository;
    private final PasswordEncoder passwordEncoder;
    private final EmailSenderService emailSender;

    public UserService(UserRepository userRepository, PasswordEncoder passwordEncoder, EmailSenderService emailSender) {
        this.userRepository = userRepository;
        this.passwordEncoder = passwordEncoder;
        this.emailSender = emailSender;
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
}
