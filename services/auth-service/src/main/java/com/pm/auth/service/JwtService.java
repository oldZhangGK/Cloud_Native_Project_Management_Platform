package com.pm.auth.service;

import com.pm.auth.domain.RoleName;
import com.pm.auth.domain.User;
import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;

import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.time.Instant;
import java.util.Date;
import java.util.List;
import java.util.UUID;

@Service
public class JwtService {

    private final RSAPrivateKey privateKey;
    private final RSAPublicKey publicKey;
    private final long accessTokenExpirySeconds;

    public JwtService(
            RSAPrivateKey rsaPrivateKey,
            RSAPublicKey rsaPublicKey,
            @Value("${app.jwt.access-token-expiry-seconds}") long accessTokenExpirySeconds) {
        this.privateKey = rsaPrivateKey;
        this.publicKey = rsaPublicKey;
        this.accessTokenExpirySeconds = accessTokenExpirySeconds;
    }

    public String generateAccessToken(User user) {
        Instant now = Instant.now();
        List<String> roles = user.getRoles().stream()
            .map(r -> r.getName().name())
            .toList();

        return Jwts.builder()
            .subject(user.getId().toString())
            .claim("email", user.getEmail())
            .claim("roles", roles)
            .id(UUID.randomUUID().toString())
            .issuedAt(Date.from(now))
            .expiration(Date.from(now.plusSeconds(accessTokenExpirySeconds)))
            .signWith(privateKey)
            .compact();
    }

    public Claims validateAndParseClaims(String token) {
        return Jwts.parser()
            .verifyWith(publicKey)
            .build()
            .parseSignedClaims(token)
            .getPayload();
    }

    public long getAccessTokenExpirySeconds() {
        return accessTokenExpirySeconds;
    }

    public RSAPublicKey getPublicKey() {
        return publicKey;
    }
}
