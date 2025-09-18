package com.bsep.pki_system.config;

import org.springframework.context.annotation.Bean;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.stereotype.Component;

@Component
public class SecurityConfig {

    @Bean
    public SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
        http
                .csrf(csrf -> csrf.disable()) // optional for testing
                .authorizeHttpRequests(auth -> auth
                        .requestMatchers("/hello").permitAll() // allow /hello without login
                        .anyRequest().authenticated()
                )
                .httpBasic(); // basic auth (optional)
        return http.build();
    }
}