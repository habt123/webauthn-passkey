package com.example.fido2poc.controller;

import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/.well-known/apple-app-site-association")
public class WellKnownEndpoint {

  //This is the well-known endpoint for Passkey Authentication.
  @GetMapping
  public ResponseEntity<String> getWellKnownEndpoint() {
    String response = """
        {
            "webauthn": {
                "apps": [
                    "TEAMID.omnissa.FIDOSecureEnclave"
                ]
            }
        }
        """;
    return ResponseEntity.ok(response);
  }
}
