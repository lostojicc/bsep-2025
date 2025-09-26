package com.bsep.pki_system.controller;

import com.bsep.pki_system.dto.CertificateIssueDTO;
import com.bsep.pki_system.exceptions.CertificateGenerationException;
import com.bsep.pki_system.jwt.JwtService;
import com.bsep.pki_system.model.Certificate;
import com.bsep.pki_system.service.CertificateService;
import jakarta.servlet.http.HttpServletRequest;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.*;

import java.security.cert.CertificateEncodingException;
import java.security.cert.X509Certificate;
import java.util.Arrays;

@RestController
@RequestMapping("/certificate")
public class CertificateController {

    private final CertificateService certificateService;
    private final JwtService jwtService;

    public CertificateController(CertificateService certificateService, JwtService jwtService) {
        this.certificateService = certificateService;
        this.jwtService = jwtService;
    }

    @PostMapping("/root")
    @PreAuthorize("hasRole('ADMIN')")
    public ResponseEntity<String> createRootCertificate(@RequestParam long adminId) {
        try {
            Certificate rootCert = certificateService.generateRootCertificate(adminId);
            return ResponseEntity.ok("Root certificate created: " + rootCert.getAlias());
        } catch (CertificateGenerationException e) {
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR)
                    .body("Error: " + e.getMessage());
        }
    }

    @GetMapping("/root/download")
    public ResponseEntity<byte[]> downloadRootCertificate(@RequestParam String alias) {
        try {
            X509Certificate cert = certificateService.loadCertificateFromKeystore(alias);

            // Encode certificate in DER format (binary)
            byte[] certBytes = cert.getEncoded();

            return ResponseEntity.ok()
                    .header("Content-Disposition", "attachment; filename=\"" + alias + ".cer\"")
                    .header("Content-Type", "application/x-x509-ca-cert")
                    .body(certBytes);

        } catch (CertificateGenerationException | CertificateEncodingException e) {
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR)
                    .body(null);
        }
    }

    @PostMapping("/issue-ca")
    @PreAuthorize("hasAnyRole('ADMIN', 'CA')")
    public ResponseEntity<String> issueCACertificate(@RequestBody CertificateIssueDTO issue, HttpServletRequest request) {
        try {
            String token = JwtService.extractTokenFromRequest(request);
            certificateService.issueCACertificate(issue, jwtService.getUserIdFromToken(token));
            return ResponseEntity.ok("Certificate issued");
        } catch (Exception e) {
            e.printStackTrace();
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR).body("Error: " + e.getMessage());
        }
    }
}
