(function () {
    "use strict";

    function detectBrowserSupport() {
        return window.PublicKeyCredential !== undefined &&
            typeof window.PublicKeyCredential === "function";
    }

    // Convert a base64url string to a Uint8Array (required by WebAuthn API).
    function base64UrlToByteArray(base64String) {
        var padded = base64String.replace(/-/g, '+').replace(/_/g, '/');
        while (padded.length % 4 !== 0) {
            padded += '=';
        }
        return Uint8Array.from(atob(padded), function (c) {
            return c.charCodeAt(0);
        });
    }

    // Convert an ArrayBuffer to a base64url string.
    function byteArrayToBase64Url(buffer) {
        return btoa(new Uint8Array(buffer).reduce(function (s, byte) {
            return s + String.fromCharCode(byte);
        }, ''))
            .replace(/\+/g, "-")
            .replace(/\//g, "_")
            .replace(/=/g, "");
    }

    // Convert IDs in PublicKeyCredentialCreationOptions from base64url strings to byte arrays.
    function convertCreationOptionsIds(options) {
        options.challenge = base64UrlToByteArray(options.challenge);
        options.user.id = base64UrlToByteArray(options.user.id);
        if (options.excludeCredentials) {
            options.excludeCredentials.forEach(function (cred) {
                cred.id = base64UrlToByteArray(cred.id);
            });
        }
    }

    // Convert IDs in PublicKeyCredentialRequestOptions from base64url strings to byte arrays.
    function convertRequestOptionsIds(options) {
        options.challenge = base64UrlToByteArray(options.challenge);
        if (options.allowCredentials) {
            options.allowCredentials.forEach(function (cred) {
                cred.id = base64UrlToByteArray(cred.id);
            });
        }
    }

    async function registerPasskey(username) {
        var optionsResponse = await fetch('/api/register/options', {
            method: 'POST',
            headers: {'Content-Type': 'application/json'},
            body: JSON.stringify({username: username})
        });

        if (!optionsResponse.ok) {
            var err = await optionsResponse.json();
            throw new Error(err.errorMessage || 'Failed to get registration options');
        }

        var options = await optionsResponse.json();
        convertCreationOptionsIds(options);

        var credential = await navigator.credentials.create({publicKey: options});

        var attestationResponse = {
            username: username,
            id: credential.id,
            rawId: byteArrayToBase64Url(credential.rawId),
            type: credential.type,
            response: {
                attestationObject: byteArrayToBase64Url(credential.response.attestationObject),
                clientDataJSON: byteArrayToBase64Url(credential.response.clientDataJSON)
            }
        };

        var verifyResponse = await fetch('/api/register/verify', {
            method: 'POST',
            headers: {'Content-Type': 'application/json'},
            body: JSON.stringify(attestationResponse)
        });

        if (!verifyResponse.ok) {
            var verifyErr = await verifyResponse.json();
            throw new Error(verifyErr.errorMessage || 'Attestation verification failed');
        }

        return await verifyResponse.json();
    }

    async function loginPasskey(username) {
        var optionsResponse = await fetch('/api/login/options', {
            method: 'POST',
            headers: {'Content-Type': 'application/json'},
            body: JSON.stringify({username: username || ''})
        });

        if (!optionsResponse.ok) {
            var err = await optionsResponse.json();
            throw new Error(err.errorMessage || 'Failed to get login options');
        }

        var options = await optionsResponse.json();
        convertRequestOptionsIds(options);

        var assertion = await navigator.credentials.get({publicKey: options});

        var assertionResponse = {
            username: username || '',
            id: assertion.id,
            rawId: byteArrayToBase64Url(assertion.rawId),
            type: assertion.type,
            response: {
                authenticatorData: byteArrayToBase64Url(assertion.response.authenticatorData),
                clientDataJSON: byteArrayToBase64Url(assertion.response.clientDataJSON),
                signature: byteArrayToBase64Url(assertion.response.signature),
                userHandle: assertion.response.userHandle
                    ? byteArrayToBase64Url(assertion.response.userHandle)
                    : ''
            }
        };

        var verifyResponse = await fetch('/api/login/verify', {
            method: 'POST',
            headers: {'Content-Type': 'application/json'},
            body: JSON.stringify(assertionResponse)
        });

        if (!verifyResponse.ok) {
            var verifyErr = await verifyResponse.json();
            throw new Error(verifyErr.errorMessage || 'Assertion verification failed');
        }

        return await verifyResponse.json();
    }

    window.webauthn = {
        detectBrowserSupport: detectBrowserSupport,
        registerPasskey: registerPasskey,
        loginPasskey: loginPasskey
    };
})();
