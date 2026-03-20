package com.example.fido2poc.controller;

import com.example.fido2poc.dto.AttestationRequest;
import com.example.fido2poc.dto.UserRegistrationRequest;
import com.example.fido2poc.service.RegistrationService;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.util.Map;

@RestController
@RequestMapping("/api/register")
public class RegistrationController {

    private static final Logger LOGGER = LoggerFactory.getLogger(RegistrationController.class);
    private final RegistrationService registrationService;

    public RegistrationController(RegistrationService registrationService) {
        this.registrationService = registrationService;
    }

    @PostMapping("/user")
    public ResponseEntity<?> registerUser(@RequestBody UserRegistrationRequest request) {
        try {
            LOGGER.info("Registering user: {}", request.getUsername());
            Map<String, Object> result = registrationService.registerUser(
                    request.getUsername(), request.getDisplayName());
            return ResponseEntity.ok(result);
        } catch (IllegalArgumentException e) {
            LOGGER.error("Error occurred while verify assertion", e);
            return ResponseEntity.badRequest().body(Map.of("errorMessage", e.getMessage()));
        }
    }

    @PostMapping("/options")
    public ResponseEntity<?> getRegistrationOptions(@RequestBody Map<String, String> request) {
        try {
            String username = request.get("username");
            Map<String, Object> options = registrationService.generateRegistrationOptions(username);
            LOGGER.info("Registration options: {}", options);
            return ResponseEntity.ok(options);
        } catch (IllegalArgumentException e) {
            LOGGER.error("Error occurred while verify assertion", e);
            return ResponseEntity.badRequest().body(Map.of("errorMessage", e.getMessage()));
        }
    }

    @PostMapping("/verify")
    public ResponseEntity<?> verifyAttestation(@RequestBody AttestationRequest request) {
        LOGGER.info("Verifying attestation: {}", request.getUsername());
        try {
            Map<String, String> result = registrationService.verifyAttestation(request);
            return ResponseEntity.ok(result);
        } catch (Exception e) {
            LOGGER.error("Error occurred while verify assertion", e);
            return ResponseEntity.badRequest().body(Map.of("errorMessage", e.getMessage()));
        }
    }
}
