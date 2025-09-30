package com.bsep.pki_system.controller;


import com.bsep.pki_system.jwt.JwtService;
import com.bsep.pki_system.model.CSR;
import com.bsep.pki_system.service.CsrService;
import jakarta.servlet.http.HttpServletRequest;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.multipart.MultipartFile;

import java.security.Principal;
import java.util.HashMap;
import java.util.Map;

@RestController
@RequestMapping("/csr")
public class CsrController {

    private final CsrService csrService;
    private final JwtService jwtService;

    public CsrController(CsrService csrService, JwtService jwtService) {
        this.csrService = csrService;
        this.jwtService = jwtService;
    }

    @PostMapping("/api/csr/upload")
    @PreAuthorize("hasRole('USER')")
    public ResponseEntity<?> uploadCsr(@RequestParam("file") MultipartFile file,
                                       @RequestParam("caId") Long caId,
                                       @RequestParam("validityDays") int validityDays
                                       , HttpServletRequest request) {

        String token = JwtService.extractTokenFromRequest(request);
        String email = jwtService.getEmailFromToken(token) ;
        String clientIp = request.getRemoteAddr(); //opkusacu za logove

        try{
            CSR savedCSR = csrService.handleUpload(file, caId, validityDays, email, clientIp);

            Map<String, Object> response = new HashMap<>();
            response.put("id", savedCSR.getId());
            response.put("status", savedCSR.getStatus());
            response.put("fingerprint", savedCSR.getCsrFingerprint());
            response.put("createdAt", savedCSR.getCreatedAt());

            return ResponseEntity.status(HttpStatus.CREATED).body(response);
        }
        catch (IllegalArgumentException e) {
            return ResponseEntity.badRequest().body(e.getMessage());
        } catch (Exception e) {
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR).body("Server error");
        }
    }
}
