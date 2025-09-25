package com.bsep.pki_system.dto;

import lombok.AllArgsConstructor;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;

import java.security.PrivateKey;
import java.security.cert.X509Certificate;
import java.util.List;

@Getter
@Setter
@NoArgsConstructor
@AllArgsConstructor
public class KeyStoreEntry {
    private String alias;
    private String password;
    private PrivateKey privateKey;
    private List<X509Certificate> certificateChain;
    private long userId;
    private String organization;
}
