package com.bsep.pki_system.service;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.ResponseEntity;
import org.springframework.stereotype.Service;
import org.springframework.util.LinkedMultiValueMap;
import org.springframework.util.MultiValueMap;
import org.springframework.web.client.RestTemplate;

import java.util.Map;

@Service
public class CaptchaService {

    private final String secretKey;

    public CaptchaService(@Value("${recaptcha.secret}") String secretKey) {
        this.secretKey = secretKey;
    }

    public boolean verifyToken(String token) {
        RestTemplate restTemplate = new RestTemplate();
        String url = "https://www.google.com/recaptcha/api/siteverify";

        MultiValueMap<String, String> params = new LinkedMultiValueMap<>();
        params.add("secret", secretKey);
        params.add("response", token);

        ResponseEntity<Map> response = restTemplate.postForEntity(url, params, Map.class);
        Map body = response.getBody();
        return body != null && Boolean.TRUE.equals(body.get("success"));
    }
}