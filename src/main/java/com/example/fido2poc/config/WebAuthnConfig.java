package com.example.fido2poc.config;

import com.webauthn4j.WebAuthnAuthenticationManager;
import com.webauthn4j.WebAuthnManager;
import com.webauthn4j.verifier.attestation.statement.none.NoneAttestationStatementVerifier;
import com.webauthn4j.verifier.attestation.statement.packed.PackedAttestationStatementVerifier;
import com.webauthn4j.verifier.attestation.trustworthiness.self.DefaultSelfAttestationTrustworthinessVerifier;
import com.webauthn4j.verifier.attestation.trustworthiness.certpath.NullCertPathTrustworthinessVerifier;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

import java.util.List;

@Configuration
public class WebAuthnConfig {

    @Bean
    public WebAuthnManager webAuthnManager() {
        DefaultSelfAttestationTrustworthinessVerifier selfVerifier =
                new DefaultSelfAttestationTrustworthinessVerifier();
        selfVerifier.setSelfAttestationAllowed(true);

        return new WebAuthnManager(
                List.of(new NoneAttestationStatementVerifier(), new PackedAttestationStatementVerifier()),
                new NullCertPathTrustworthinessVerifier(),
                selfVerifier);
    }

    @Bean
    public WebAuthnAuthenticationManager webAuthnAuthenticationManager() {
        return new WebAuthnAuthenticationManager();
    }
}
