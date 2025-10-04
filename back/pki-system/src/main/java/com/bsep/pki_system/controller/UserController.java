package com.bsep.pki_system.controller;

import com.bsep.pki_system.dto.CaUserDTO;
import com.bsep.pki_system.model.User;
import com.bsep.pki_system.service.UserService;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.util.List;

@RestController
@RequestMapping("/user")
public class UserController {

    private final UserService userService;

    public UserController(UserService userService) {
        this.userService = userService;
    }

    @GetMapping("/cas")
    @PreAuthorize("hasRole('BASIC')")
    public ResponseEntity<List<CaUserDTO>> getAllCAs() {
        List<CaUserDTO> caUsers = userService.getAllCAs();
        return ResponseEntity.ok(caUsers);
    }
}
