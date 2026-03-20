package com.example.fido2poc.service;

import com.example.fido2poc.dto.AssertionRequest;
import com.example.fido2poc.model.CredentialEntity;
import com.example.fido2poc.model.UserEntity;
import com.example.fido2poc.repository.CredentialRepository;
import com.example.fido2poc.repository.UserRepository;
import com.webauthn4j.WebAuthnAuthenticationManager;
import com.webauthn4j.authenticator.Authenticator;
import com.webauthn4j.converter.util.CborConverter;
import com.webauthn4j.converter.util.ObjectConverter;
import com.webauthn4j.data.AuthenticationData;
import com.webauthn4j.data.AuthenticationParameters;
import com.webauthn4j.data.AuthenticationRequest;
import com.webauthn4j.data.attestation.authenticator.AAGUID;
import com.webauthn4j.data.attestation.authenticator.AttestedCredentialData;
import com.webauthn4j.data.attestation.authenticator.COSEKey;
import com.webauthn4j.data.client.Origin;
import com.webauthn4j.data.client.challenge.Challenge;
import com.webauthn4j.data.client.challenge.DefaultChallenge;
import com.webauthn4j.server.ServerProperty;
import com.webauthn4j.util.Base64UrlUtil;
import jakarta.annotation.PostConstruct;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;

import java.security.SecureRandom;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

@Service
public class LoginService {

    private static final Logger LOGGER = LoggerFactory.getLogger(LoginService.class);
    private static final SecureRandom SECURE_RANDOM = new SecureRandom();

    private final UserRepository userRepository;
    private final CredentialRepository credentialRepository;
    private final WebAuthnAuthenticationManager webAuthnAuthenticationManager;
    private final ObjectConverter objectConverter;
    private final ConcurrentHashMap<String, byte[]> challengeStore = new ConcurrentHashMap<>();

    @Value("${webauthn.rp.id}")
    private String rpId;

    @Value("${webauthn.rp.origin}")
    private String origin;

    public LoginService(UserRepository userRepository, CredentialRepository credentialRepository,
                        WebAuthnAuthenticationManager webAuthnAuthenticationManager,
                        ObjectConverter objectConverter) {
        this.userRepository = userRepository;
        this.credentialRepository = credentialRepository;
        this.webAuthnAuthenticationManager = webAuthnAuthenticationManager;
        this.objectConverter = objectConverter;
    }

    @PostConstruct
    public void init() {
        LOGGER.info("LoginService initialized with rpId: {}, origin: {}", rpId, origin);
    }

    public Map<String, Object> generateLoginOptions(String username) {
        byte[] challengeBytes = new byte[32];
        SECURE_RANDOM.nextBytes(challengeBytes);
        LOGGER.info("Generating challenge for username: {}", username);

        String challengeKey = (username != null && !username.isBlank()) ? username : "__discoverable__";
        challengeStore.put(challengeKey, challengeBytes);

        String challengeBase64 = Base64UrlUtil.encodeToString(challengeBytes);

        Map<String, Object> options = new LinkedHashMap<>();
        options.put("challenge", challengeBase64);
        options.put("rpId", rpId);
        options.put("timeout", 60000);
        options.put("userVerification", "preferred");

        if (username != null && !username.isBlank()) {
            UserEntity user = userRepository.findByUsername(username)
                    .orElseThrow(() -> new IllegalArgumentException("User not found: " + username));

            List<CredentialEntity> credentials = credentialRepository.findByUserId(user.getId());
            if (credentials.isEmpty()) {
                LOGGER.warn("No credentials found for user: {}", username);
                throw new IllegalStateException("No passkeys registered for user: " + username);
            }

            LOGGER.info("Found credentials for user: {}", username);
            List<Map<String, Object>> allowCredentials = credentials.stream()
                    .map(c -> {
                        Map<String, Object> desc = new LinkedHashMap<>();
                        desc.put("type", "public-key");
                        desc.put("id", c.getCredentialId());
                        return desc;
                    }).toList();
            options.put("allowCredentials", allowCredentials);
        }

        return options;
    }

    public Map<String, Object> verifyAssertion(AssertionRequest request) {
        String username = request.getUsername();
        String challengeKey = (username != null && !username.isBlank()) ? username : "__discoverable__";

        LOGGER.info("Verifying assertion for username: {}", username);
        byte[] challengeBytes = challengeStore.remove(challengeKey);
        if (challengeBytes == null) {
            throw new IllegalStateException("No pending login challenge");
        }

        String credentialIdBase64 = request.getId();
        CredentialEntity storedCredential = credentialRepository.findByCredentialId(credentialIdBase64)
                .orElseThrow(() -> new IllegalArgumentException("Unknown credential"));

        UserEntity user = userRepository.findById(storedCredential.getUserId())
                .orElseThrow(() -> new IllegalArgumentException("User not found for credential"));

        byte[] credentialId = Base64UrlUtil.decode(request.getRawId());
        byte[] authenticatorData = Base64UrlUtil.decode(request.getResponse().get("authenticatorData"));
        byte[] clientDataJSON = Base64UrlUtil.decode(request.getResponse().get("clientDataJSON"));
        byte[] signature = Base64UrlUtil.decode(request.getResponse().get("signature"));
        String userHandleStr = request.getResponse().get("userHandle");
        byte[] userHandle = (userHandleStr != null && !userHandleStr.isEmpty())
                ? Base64UrlUtil.decode(userHandleStr) : null;

        AuthenticationRequest authenticationRequest = new AuthenticationRequest(
                credentialId, userHandle, authenticatorData, clientDataJSON, signature);

        AuthenticationData authenticationData = webAuthnAuthenticationManager.parse(authenticationRequest);

        CborConverter cborConverter = objectConverter.getCborConverter();
        COSEKey coseKey = cborConverter.readValue(storedCredential.getPublicKeyCose(), COSEKey.class);

        AttestedCredentialData attestedCredentialData = new AttestedCredentialData(
                new AAGUID(storedCredential.getAaguid()),
                Base64UrlUtil.decode(storedCredential.getCredentialId()),
                coseKey);

        Authenticator authenticator = new AuthenticatorImpl(
                attestedCredentialData, storedCredential.getSignCount());

        Challenge challenge = new DefaultChallenge(challengeBytes);
        Origin originObj = new Origin(origin);
        ServerProperty serverProperty = new ServerProperty(originObj, rpId, challenge);

        AuthenticationParameters authenticationParameters = new AuthenticationParameters(
                serverProperty, authenticator, false, true);

        webAuthnAuthenticationManager.verify(authenticationData, authenticationParameters);

        long newCount = authenticationData.getAuthenticatorData().getSignCount();
        storedCredential.setSignCount(newCount);
        credentialRepository.save(storedCredential);

        Map<String, Object> result = new LinkedHashMap<>();
        result.put("status", "ok");
        result.put("username", user.getUsername());
        LOGGER.info("Verified credentials for user: {}", user.getUsername());
        return result;
    }

    private static class AuthenticatorImpl implements Authenticator {
        private final AttestedCredentialData attestedCredentialData;
        private long counter;

        AuthenticatorImpl(AttestedCredentialData attestedCredentialData, long counter) {
            this.attestedCredentialData = attestedCredentialData;
            this.counter = counter;
        }

        @Override
        public AttestedCredentialData getAttestedCredentialData() {
            return attestedCredentialData;
        }

        @Override
        public long getCounter() {
            return counter;
        }

        @Override
        public void setCounter(long value) {
            this.counter = value;
        }
    }
}
