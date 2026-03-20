package com.example.fido2poc.controller;

import com.example.fido2poc.dto.AssertionRequest;
import com.example.fido2poc.service.LoginService;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.util.Map;

@RestController
@RequestMapping("/api/login")
public class LoginController {

    private static final Logger LOGGER = LoggerFactory.getLogger(LoginController.class);
    private final LoginService loginService;

    public LoginController(LoginService loginService) {
        this.loginService = loginService;
    }

    @PostMapping("/options")
    public ResponseEntity<?> getLoginOptions(@RequestBody Map<String, String> request) {
        try {
            String username = request.get("username");
            Map<String, Object> options = loginService.generateLoginOptions(username);
            LOGGER.info("Login options: {}", options);
            return ResponseEntity.ok(options);
        } catch (Exception e) {
            LOGGER.error("Error occurred while getting login options", e);
            return ResponseEntity.badRequest().body(Map.of("errorMessage", e.getMessage()));
        }
    }

    @PostMapping("/verify")
    public ResponseEntity<?> verifyAssertion(@RequestBody AssertionRequest request) {
        try {
            Map<String, Object> result = loginService.verifyAssertion(request);
            LOGGER.info("Verify assertion: {}", result);
            return ResponseEntity.ok(result);
        } catch (Exception e) {
            LOGGER.error("Error occurred while verify assertion", e);
            return ResponseEntity.badRequest().body(Map.of("errorMessage", e.getMessage()));
        }
    }
}
