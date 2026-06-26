package com.pm.auth.service;

import com.pm.auth.domain.PasswordResetToken;
import com.pm.auth.domain.User;
import com.pm.auth.event.UserEventPublisher;
import com.pm.auth.exception.PasswordResetException;
import com.pm.auth.repository.PasswordResetTokenRepository;
import com.pm.auth.repository.RefreshTokenRepository;
import com.pm.auth.repository.UserRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.Base64;
import java.util.Optional;

@Service
@RequiredArgsConstructor
public class PasswordResetService {

    private final UserRepository userRepository;
    private final PasswordResetTokenRepository resetTokenRepository;
    private final RefreshTokenRepository refreshTokenRepository;
    private final PasswordEncoder passwordEncoder;
    private final UserEventPublisher userEventPublisher;

    public record ResetRequestResult(String message, String resetToken) {}

    @Transactional
    public ResetRequestResult requestReset(String email) {
        String normalizedEmail = email.toLowerCase().trim();
        Optional<User> userOpt = userRepository.findByEmail(normalizedEmail);

        // Always return the same message to prevent user enumeration
        String genericMessage = "If an account exists with that email, a reset link has been sent.";

        if (userOpt.isEmpty()) {
            return new ResetRequestResult(genericMessage, null);
        }

        User user = userOpt.get();
        String rawToken = generateSecureToken();

        PasswordResetToken resetToken = new PasswordResetToken();
        resetToken.setUserId(user.getId());
        resetToken.setTokenHash(hashToken(rawToken));
        resetToken.setExpiresAt(Instant.now().plus(1, ChronoUnit.HOURS));

        resetTokenRepository.save(resetToken);

        // Phase 1: return raw token in response for local testing
        // Phase 2: send via email delivery service instead
        return new ResetRequestResult(genericMessage, rawToken);
    }

    @Transactional
    public void confirmReset(String rawToken, String newPassword) {
        PasswordResetToken resetToken = resetTokenRepository.findByTokenHash(hashToken(rawToken))
            .orElseThrow(() -> new PasswordResetException("TOKEN_INVALID", "Reset token is invalid"));

        if (resetToken.isUsed()) {
            throw new PasswordResetException("TOKEN_ALREADY_USED", "Reset token has already been used");
        }

        if (resetToken.getExpiresAt().isBefore(Instant.now())) {
            throw new PasswordResetException("TOKEN_EXPIRED", "Reset token has expired");
        }

        User user = userRepository.findById(resetToken.getUserId())
            .orElseThrow(() -> new IllegalStateException("User not found for reset token"));

        user.setPasswordHash(passwordEncoder.encode(newPassword));
        userRepository.save(user);

        resetToken.setUsed(true);
        resetToken.setUsedAt(Instant.now());
        resetTokenRepository.save(resetToken);

        // Revoke all refresh tokens so existing sessions can't be continued post-password-change
        refreshTokenRepository.revokeAllForUser(user.getId(), Instant.now());

        userEventPublisher.publishPasswordChanged(user.getId(), user.getEmail());
    }

    private String generateSecureToken() {
        byte[] bytes = new byte[32];
        new SecureRandom().nextBytes(bytes);
        return Base64.getUrlEncoder().withoutPadding().encodeToString(bytes);
    }

    private String hashToken(String rawToken) {
        try {
            MessageDigest digest = MessageDigest.getInstance("SHA-256");
            byte[] hash = digest.digest(rawToken.getBytes(StandardCharsets.UTF_8));
            return Base64.getEncoder().encodeToString(hash);
        } catch (NoSuchAlgorithmException e) {
            throw new IllegalStateException("SHA-256 not available", e);
        }
    }
}
