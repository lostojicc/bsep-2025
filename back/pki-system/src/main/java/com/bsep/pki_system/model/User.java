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
@Table(name = "app_user")
public class User {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    private String name;
    private String surname;

    @Column(unique = true, nullable = false)
    private String email;

    private String password;

    private String organization;

    private boolean activated = false;

    @Enumerated(EnumType.STRING)
    private UserRole role;

    private String activationToken;
    private LocalDateTime activationTokenExpiry;
}