package com.pm.auth.service;

import com.pm.auth.domain.RefreshToken;
import com.pm.auth.exception.TokenExpiredException;
import com.pm.auth.exception.TokenInvalidException;
import com.pm.auth.exception.TokenReuseDetectedException;
import com.pm.auth.repository.RefreshTokenRepository;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.ArgumentCaptor;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.test.util.ReflectionTestUtils;

import java.time.Instant;
import java.util.Optional;
import java.util.UUID;

import static org.assertj.core.api.Assertions.*;
import static org.mockito.ArgumentMatchers.*;
import static org.mockito.Mockito.*;

@ExtendWith(MockitoExtension.class)
class RefreshTokenServiceTest {

    @Mock private RefreshTokenRepository refreshTokenRepository;
    @InjectMocks private RefreshTokenService refreshTokenService;

    @BeforeEach
    void setUp() {
        ReflectionTestUtils.setField(refreshTokenService, "refreshTokenExpirySeconds", 604800L);
    }

    // --- issueToken ---

    @Test
    void issueToken_savesTokenAndReturnsRawToken() {
        UUID userId = UUID.randomUUID();
        UUID familyId = UUID.randomUUID();
        when(refreshTokenRepository.save(any(RefreshToken.class))).thenAnswer(inv -> inv.getArgument(0));

        String rawToken = refreshTokenService.issueToken(userId, familyId);

        assertThat(rawToken).isNotBlank();
        ArgumentCaptor<RefreshToken> captor = ArgumentCaptor.forClass(RefreshToken.class);
        verify(refreshTokenRepository).save(captor.capture());
        RefreshToken saved = captor.getValue();
        assertThat(saved.getUserId()).isEqualTo(userId);
        assertThat(saved.getFamilyId()).isEqualTo(familyId);
        assertThat(saved.isRevoked()).isFalse();
    }

    @Test
    void issueToken_hashIsDifferentFromRawToken() {
        UUID userId = UUID.randomUUID();
        UUID familyId = UUID.randomUUID();
        when(refreshTokenRepository.save(any(RefreshToken.class))).thenAnswer(inv -> inv.getArgument(0));

        String rawToken = refreshTokenService.issueToken(userId, familyId);
        String hash = refreshTokenService.hashToken(rawToken);

        assertThat(hash).isNotEqualTo(rawToken);
    }

    // --- rotate ---

    @Test
    void rotate_withValidToken_revokesOldAndReturnsNewToken() {
        UUID userId = UUID.randomUUID();
        UUID familyId = UUID.randomUUID();
        String rawToken = "raw-test-token";
        String hash = refreshTokenService.hashToken(rawToken);

        RefreshToken stored = buildToken(userId, familyId, hash, false, Instant.now().plusSeconds(3600));
        when(refreshTokenRepository.findByTokenHash(hash)).thenReturn(Optional.of(stored));
        when(refreshTokenRepository.save(any())).thenAnswer(inv -> inv.getArgument(0));

        RefreshTokenService.RotateResult result = refreshTokenService.rotate(rawToken);

        assertThat(result.userId()).isEqualTo(userId);
        assertThat(result.newRawToken()).isNotBlank().isNotEqualTo(rawToken);
        assertThat(stored.isRevoked()).isTrue();
        assertThat(stored.getRevokedAt()).isNotNull();
    }

    @Test
    void rotate_withRevokedToken_revokesFamily_throwsTokenReuseDetected() {
        UUID userId = UUID.randomUUID();
        UUID familyId = UUID.randomUUID();
        String rawToken = "raw-test-token";
        String hash = refreshTokenService.hashToken(rawToken);

        RefreshToken stored = buildToken(userId, familyId, hash, true, Instant.now().plusSeconds(3600));
        when(refreshTokenRepository.findByTokenHash(hash)).thenReturn(Optional.of(stored));

        assertThatThrownBy(() -> refreshTokenService.rotate(rawToken))
            .isInstanceOf(TokenReuseDetectedException.class);

        verify(refreshTokenRepository).revokeFamily(eq(familyId), any(Instant.class));
    }

    @Test
    void rotate_withExpiredToken_throwsTokenExpired() {
        UUID userId = UUID.randomUUID();
        UUID familyId = UUID.randomUUID();
        String rawToken = "raw-test-token";
        String hash = refreshTokenService.hashToken(rawToken);

        RefreshToken stored = buildToken(userId, familyId, hash, false, Instant.now().minusSeconds(1));
        when(refreshTokenRepository.findByTokenHash(hash)).thenReturn(Optional.of(stored));

        assertThatThrownBy(() -> refreshTokenService.rotate(rawToken))
            .isInstanceOf(TokenExpiredException.class);
    }

    @Test
    void rotate_withUnknownToken_throwsTokenInvalid() {
        String rawToken = "unknown-token";
        when(refreshTokenRepository.findByTokenHash(anyString())).thenReturn(Optional.empty());

        assertThatThrownBy(() -> refreshTokenService.rotate(rawToken))
            .isInstanceOf(TokenInvalidException.class);
    }

    // --- revokeToken ---

    @Test
    void revokeToken_withValidToken_setsRevoked() {
        UUID userId = UUID.randomUUID();
        UUID familyId = UUID.randomUUID();
        String rawToken = "raw-test-token";
        String hash = refreshTokenService.hashToken(rawToken);

        RefreshToken stored = buildToken(userId, familyId, hash, false, Instant.now().plusSeconds(3600));
        when(refreshTokenRepository.findByTokenHash(hash)).thenReturn(Optional.of(stored));
        when(refreshTokenRepository.save(any())).thenAnswer(inv -> inv.getArgument(0));

        refreshTokenService.revokeToken(rawToken);

        assertThat(stored.isRevoked()).isTrue();
        verify(refreshTokenRepository).save(stored);
    }

    @Test
    void revokeToken_withUnknownToken_doesNothing() {
        when(refreshTokenRepository.findByTokenHash(anyString())).thenReturn(Optional.empty());
        assertThatCode(() -> refreshTokenService.revokeToken("unknown")).doesNotThrowAnyException();
        verify(refreshTokenRepository, never()).save(any());
    }

    // --- revokeAllForUser ---

    @Test
    void revokeAllForUser_callsRepository() {
        UUID userId = UUID.randomUUID();
        refreshTokenService.revokeAllForUser(userId);
        verify(refreshTokenRepository).revokeAllForUser(eq(userId), any(Instant.class));
    }

    private RefreshToken buildToken(UUID userId, UUID familyId, String tokenHash,
                                     boolean revoked, Instant expiresAt) {
        RefreshToken token = new RefreshToken();
        token.setId(UUID.randomUUID());
        token.setUserId(userId);
        token.setFamilyId(familyId);
        token.setTokenHash(tokenHash);
        token.setRevoked(revoked);
        token.setExpiresAt(expiresAt);
        return token;
    }
}
