package com.pm.auth.service;

import com.pm.auth.domain.RefreshToken;
import com.pm.auth.exception.TokenExpiredException;
import com.pm.auth.exception.TokenInvalidException;
import com.pm.auth.exception.TokenReuseDetectedException;
import com.pm.auth.repository.RefreshTokenRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.time.Instant;
import java.util.Base64;
import java.util.UUID;

@Service
@RequiredArgsConstructor
public class RefreshTokenService {

    private final RefreshTokenRepository refreshTokenRepository;

    @Value("${app.jwt.refresh-token-expiry-seconds}")
    private long refreshTokenExpirySeconds;

    public record RotateResult(UUID userId, String newRawToken) {}

    @Transactional
    public String issueToken(UUID userId, UUID familyId) {
        String rawToken = generateSecureToken();

        RefreshToken token = new RefreshToken();
        token.setUserId(userId);
        token.setTokenHash(hashToken(rawToken));
        token.setFamilyId(familyId);
        token.setExpiresAt(Instant.now().plusSeconds(refreshTokenExpirySeconds));

        refreshTokenRepository.save(token);
        return rawToken;
    }

    @Transactional
    public RotateResult rotate(String rawToken) {
        RefreshToken stored = refreshTokenRepository.findByTokenHash(hashToken(rawToken))
            .orElseThrow(TokenInvalidException::new);

        if (stored.isRevoked()) {
            // Reuse detected — the old token was already used, attacker is replaying it.
            // Revoke the entire family to force a full re-login.
            refreshTokenRepository.revokeFamily(stored.getFamilyId(), Instant.now());
            throw new TokenReuseDetectedException();
        }

        if (stored.getExpiresAt().isBefore(Instant.now())) {
            throw new TokenExpiredException();
        }

        stored.setRevoked(true);
        stored.setRevokedAt(Instant.now());
        refreshTokenRepository.save(stored);

        String newRawToken = issueToken(stored.getUserId(), stored.getFamilyId());
        return new RotateResult(stored.getUserId(), newRawToken);
    }

    @Transactional
    public void revokeToken(String rawToken) {
        refreshTokenRepository.findByTokenHash(hashToken(rawToken)).ifPresent(token -> {
            if (!token.isRevoked()) {
                token.setRevoked(true);
                token.setRevokedAt(Instant.now());
                refreshTokenRepository.save(token);
            }
        });
    }

    @Transactional
    public void revokeAllForUser(UUID userId) {
        refreshTokenRepository.revokeAllForUser(userId, Instant.now());
    }

    private String generateSecureToken() {
        byte[] bytes = new byte[32];
        new SecureRandom().nextBytes(bytes);
        return Base64.getUrlEncoder().withoutPadding().encodeToString(bytes);
    }

    String hashToken(String rawToken) {
        try {
            MessageDigest digest = MessageDigest.getInstance("SHA-256");
            byte[] hash = digest.digest(rawToken.getBytes(StandardCharsets.UTF_8));
            return Base64.getEncoder().encodeToString(hash);
        } catch (NoSuchAlgorithmException e) {
            throw new IllegalStateException("SHA-256 not available", e);
        }
    }
}
