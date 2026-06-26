package com.pm.auth.controller;

import com.pm.auth.service.JwtService;
import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.tags.Tag;
import lombok.RequiredArgsConstructor;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.security.interfaces.RSAPublicKey;
import java.util.Arrays;
import java.util.Base64;
import java.util.List;
import java.util.Map;

@RestController
@RequestMapping("/api/v1/auth")
@RequiredArgsConstructor
@Tag(name = "Keys", description = "RSA public key distribution (JWK Set)")
public class KeyController {

    private final JwtService jwtService;

    @GetMapping("/keys")
    @Operation(summary = "Return RSA public key as JWK Set for JWT validation by downstream services")
    public ResponseEntity<Map<String, List<Map<String, String>>>> jwks() {
        RSAPublicKey publicKey = jwtService.getPublicKey();

        // BigInteger.toByteArray() prepends a 0x00 sign byte for positive values whose high bit is set;
        // JWK spec requires the unsigned big-endian encoding, so we strip it.
        byte[] modulusBytes = publicKey.getModulus().toByteArray();
        if (modulusBytes[0] == 0) {
            modulusBytes = Arrays.copyOfRange(modulusBytes, 1, modulusBytes.length);
        }

        byte[] exponentBytes = publicKey.getPublicExponent().toByteArray();
        if (exponentBytes[0] == 0) {
            exponentBytes = Arrays.copyOfRange(exponentBytes, 1, exponentBytes.length);
        }

        Base64.Encoder urlEncoder = Base64.getUrlEncoder().withoutPadding();
        Map<String, String> jwk = Map.of(
            "kty", "RSA",
            "use", "sig",
            "alg", "RS256",
            "kid", "auth-key-1",
            "n",   urlEncoder.encodeToString(modulusBytes),
            "e",   urlEncoder.encodeToString(exponentBytes)
        );

        return ResponseEntity.ok(Map.of("keys", List.of(jwk)));
    }
}
