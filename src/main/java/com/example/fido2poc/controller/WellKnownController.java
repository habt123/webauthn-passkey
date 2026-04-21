package com.example.fido2poc.controller;

import java.util.List;
import java.util.Map;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

/**
 * Serves the {@code /.well-known} association documents required for passkey
 * (WebAuthn) credential sharing between this relying party and native apps.
 *
 * <ul>
 *   <li>{@code /.well-known/apple-app-site-association} &mdash; Apple App Site
 *       Association (AASA) document. See
 *       <a href="https://developer.apple.com/documentation/xcode/supporting-associated-domains">
 *       Apple Associated Domains</a>. Apple fetches this document directly over
 *       HTTPS and rejects responses served via redirects.</li>
 *   <li>{@code /.well-known/assetlinks.json} &mdash; Google Digital Asset Links
 *       document used by Android Credential Manager. See
 *       <a href="https://developers.google.com/digital-asset-links/v1/getting-started">
 *       Digital Asset Links</a>.</li>
 * </ul>
 *
 * Production associated domain: {@code https://webauthn-passkey-production.up.railway.app/}.
 * Override the defaults via the {@code WEBAUTHN_AASA_APPS},
 * {@code WEBAUTHN_ANDROID_PACKAGE} and {@code WEBAUTHN_ANDROID_SHA256}
 * environment variables.
 */
@RestController
public class WellKnownController {

    private final List<String> aasaApps;
    private final String androidPackage;
    private final List<String> androidSha256Fingerprints;

    public WellKnownController(
            @Value("${webauthn.aasa.apps}") List<String> aasaApps,
            @Value("${webauthn.assetlinks.package}") String androidPackage,
            @Value("${webauthn.assetlinks.sha256}") List<String> androidSha256Fingerprints) {
        this.aasaApps = aasaApps;
        this.androidPackage = androidPackage;
        this.androidSha256Fingerprints = androidSha256Fingerprints;
    }

    @GetMapping(value = "/.well-known/apple-app-site-association",
            produces = MediaType.APPLICATION_JSON_VALUE)
    public ResponseEntity<Map<String, Object>> appleAppSiteAssociation() {
        Map<String, Object> body = Map.of(
                "webcredentials", Map.of("apps", aasaApps),
                "webauthn", Map.of("apps", aasaApps)
        );
        return ResponseEntity.ok(body);
    }

    @GetMapping(value = "/.well-known/assetlinks.json",
            produces = MediaType.APPLICATION_JSON_VALUE)
    public ResponseEntity<List<Map<String, Object>>> assetLinks() {
        Map<String, Object> entry = Map.of(
                "relation", List.of("delegate_permission/common.get_login_creds"),
                "target", Map.of(
                        "namespace", "android_app",
                        "package_name", androidPackage,
                        "sha256_cert_fingerprints", androidSha256Fingerprints
                )
        );
        return ResponseEntity.ok(List.of(entry));
    }
}

