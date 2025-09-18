package com.bsep.pki_system.controller;

import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
public class HelloController {

    @GetMapping("/basic")
    @PreAuthorize("hasRole('BASIC')")
    public String helloBasic() {
        return "Hello basic!";
    }

    @GetMapping("/admin")
    @PreAuthorize("hasRole('ADMIN')")
    public String helloAdmin() {
        return "Hello admin!";
    }

    @GetMapping("/ca")
    @PreAuthorize("hasRole('CA')")
    public String helloCA() {
        return "Hello ca!";
    }
}
