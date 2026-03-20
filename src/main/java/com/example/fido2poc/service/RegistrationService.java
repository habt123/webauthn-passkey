package com.example.fido2poc.service;

import com.example.fido2poc.dto.AttestationRequest;
import com.example.fido2poc.model.CredentialEntity;
import com.example.fido2poc.model.UserEntity;
import com.example.fido2poc.repository.CredentialRepository;
import com.example.fido2poc.repository.UserRepository;
import com.webauthn4j.WebAuthnManager;
import com.webauthn4j.converter.util.CborConverter;
import com.webauthn4j.converter.util.ObjectConverter;
import com.webauthn4j.data.RegistrationData;
import com.webauthn4j.data.RegistrationParameters;
import com.webauthn4j.data.RegistrationRequest;
import com.webauthn4j.data.attestation.authenticator.AttestedCredentialData;
import com.webauthn4j.data.attestation.authenticator.AuthenticatorData;
import com.webauthn4j.data.attestation.authenticator.COSEKey;
import com.webauthn4j.data.client.Origin;
import com.webauthn4j.data.client.challenge.Challenge;
import com.webauthn4j.data.client.challenge.DefaultChallenge;
import com.webauthn4j.server.ServerProperty;
import com.webauthn4j.util.Base64UrlUtil;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;

import java.nio.charset.StandardCharsets;
import java.security.SecureRandom;
import java.util.HashMap;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

@Service
public class RegistrationService {

    private static final SecureRandom SECURE_RANDOM = new SecureRandom();

    private final UserRepository userRepository;
    private final CredentialRepository credentialRepository;
    private final WebAuthnManager webAuthnManager;
    private final ObjectConverter objectConverter;
    private final ConcurrentHashMap<String, byte[]> challengeStore = new ConcurrentHashMap<>();

    @Value("${webauthn.rp.id}")
    private String rpId;

    @Value("${webauthn.rp.name}")
    private String rpName;

    @Value("${webauthn.rp.origin}")
    private String origin;

    public RegistrationService(UserRepository userRepository, CredentialRepository credentialRepository,
                               WebAuthnManager webAuthnManager, ObjectConverter objectConverter) {
        this.userRepository = userRepository;
        this.credentialRepository = credentialRepository;
        this.webAuthnManager = webAuthnManager;
        this.objectConverter = objectConverter;
    }

    public Map<String, Object> registerUser(String username, String displayName) {
        if (userRepository.existsByUsername(username)) {
            throw new IllegalArgumentException("Username already exists: " + username);
        }
        UserEntity user = userRepository.save(new UserEntity(username, displayName));
        Map<String, Object> result = new LinkedHashMap<>();
        result.put("userId", user.getId());
        result.put("username", user.getUsername());
        return result;
    }

    public Map<String, Object> generateRegistrationOptions(String username) {
        UserEntity user = userRepository.findByUsername(username)
                .orElseThrow(() -> new IllegalArgumentException("User not found: " + username));

        byte[] challengeBytes = new byte[32];
        SECURE_RANDOM.nextBytes(challengeBytes);
        challengeStore.put(username, challengeBytes);

        String challengeBase64 = Base64UrlUtil.encodeToString(challengeBytes);
        String userIdBase64 = Base64UrlUtil.encodeToString(
                user.getId().toString().getBytes(StandardCharsets.UTF_8));

        Map<String, Object> rp = new LinkedHashMap<>();
        rp.put("id", rpId);
        rp.put("name", rpName);

        Map<String, Object> userInfo = new LinkedHashMap<>();
        userInfo.put("id", userIdBase64);
        userInfo.put("name", user.getUsername());
        userInfo.put("displayName", user.getDisplayName());

        List<CredentialEntity> existing = credentialRepository.findByUserId(user.getId());
        List<Map<String, Object>> excludeCredentials = existing.stream()
                .map(c -> {
                    Map<String, Object> desc = new LinkedHashMap<>();
                    desc.put("type", "public-key");
                    desc.put("id", c.getCredentialId());
                    return desc;
                }).toList();

        Map<String, Object> authenticatorSelection = new LinkedHashMap<>();
        authenticatorSelection.put("residentKey", "preferred");
        authenticatorSelection.put("userVerification", "preferred");

        List<Map<String, Object>> pubKeyCredParams = List.of(
                Map.of("type", "public-key", "alg", -7),
                Map.of("type", "public-key", "alg", -257)
        );

        Map<String, Object> options = new LinkedHashMap<>();
        options.put("challenge", challengeBase64);
        options.put("rp", rp);
        options.put("user", userInfo);
        options.put("pubKeyCredParams", pubKeyCredParams);
        options.put("timeout", 120000);
        options.put("attestation", "none");
        options.put("authenticatorSelection", authenticatorSelection);
        if (!excludeCredentials.isEmpty()) {
            options.put("excludeCredentials", excludeCredentials);
        }

        return options;
    }

    public Map<String, String> verifyAttestation(AttestationRequest request) {
        String username = request.getUsername();
        UserEntity user = userRepository.findByUsername(username)
                .orElseThrow(() -> new IllegalArgumentException("User not found: " + username));

        byte[] challengeBytes = challengeStore.remove(username);
        if (challengeBytes == null) {
            throw new IllegalStateException("No pending registration challenge for user: " + username);
        }

        byte[] attestationObject = Base64UrlUtil.decode(request.getResponse().get("attestationObject"));
        byte[] clientDataJSON = Base64UrlUtil.decode(request.getResponse().get("clientDataJSON"));

        RegistrationRequest registrationRequest = new RegistrationRequest(attestationObject, clientDataJSON);
        RegistrationData registrationData = webAuthnManager.parse(registrationRequest);

        Challenge challenge = new DefaultChallenge(challengeBytes);
        Origin originObj = new Origin(origin);
        ServerProperty serverProperty = new ServerProperty(originObj, rpId, challenge);

        RegistrationParameters registrationParameters = new RegistrationParameters(
                serverProperty, null, false, true);

        webAuthnManager.validate(registrationData, registrationParameters);

        AuthenticatorData<?> authenticatorData = registrationData.getAttestationObject().getAuthenticatorData();
        AttestedCredentialData attestedCredentialData = authenticatorData.getAttestedCredentialData();

        byte[] credentialIdBytes = attestedCredentialData.getCredentialId();
        String credentialId = Base64UrlUtil.encodeToString(credentialIdBytes);
        String aaguid = attestedCredentialData.getAaguid().toString();
        COSEKey coseKey = attestedCredentialData.getCOSEKey();
        long signCount = authenticatorData.getSignCount();

        CborConverter cborConverter = objectConverter.getCborConverter();
        byte[] publicKeyCose = cborConverter.writeValueAsBytes(coseKey);

        CredentialEntity credential = new CredentialEntity();
        credential.setCredentialId(credentialId);
        credential.setUserId(user.getId());
        credential.setPublicKeyCose(publicKeyCose);
        credential.setAaguid(aaguid);
        credential.setSignCount(signCount);
        credential.setName(username + "'s passkey");
        credentialRepository.save(credential);

        return Map.of("status", "ok");
    }
}
