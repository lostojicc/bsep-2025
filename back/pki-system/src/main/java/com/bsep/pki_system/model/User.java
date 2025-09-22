package com.bsep.pki_system.model;

import jakarta.persistence.*;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;

import java.time.LocalDateTime;
import java.util.ArrayList;
import java.util.List;

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

    @Enumerated(EnumType.STRING)
    private UserRole role;

    // za confirm maila
    private boolean activated = false;
    private String activationToken;
    private LocalDateTime activationTokenExpiry;

    @OneToMany(mappedBy = "owner", cascade = CascadeType.REMOVE, orphanRemoval = true)
    private List<Certificate> certificates = new ArrayList<>();
}