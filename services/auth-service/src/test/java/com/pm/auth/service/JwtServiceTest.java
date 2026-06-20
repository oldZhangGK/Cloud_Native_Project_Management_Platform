package com.pm.auth.service;

import com.pm.auth.domain.Role;
import com.pm.auth.domain.RoleName;
import com.pm.auth.domain.User;
import io.jsonwebtoken.Claims;
import io.jsonwebtoken.ExpiredJwtException;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.util.List;
import java.util.Set;
import java.util.UUID;

import static org.assertj.core.api.Assertions.*;

class JwtServiceTest {

    private JwtService jwtService;
    private User testUser;

    @BeforeEach
    void setUp() throws Exception {
        KeyPairGenerator generator = KeyPairGenerator.getInstance("RSA");
        generator.initialize(2048);
        KeyPair keyPair = generator.generateKeyPair();

        jwtService = new JwtService(
            (RSAPrivateKey) keyPair.getPrivate(),
            (RSAPublicKey) keyPair.getPublic(),
            900L
        );

        Role role = new Role(RoleName.DEVELOPER, "Standard contributor");
        role.setId(UUID.randomUUID());

        testUser = new User();
        testUser.setId(UUID.randomUUID());
        testUser.setEmail("jane@example.com");
        testUser.setFirstName("Jane");
        testUser.setLastName("Doe");
        testUser.setRoles(Set.of(role));
    }

    @Test
    void generateAccessToken_returnsNonBlankToken() {
        String token = jwtService.generateAccessToken(testUser);
        assertThat(token).isNotBlank();
    }

    @Test
    void validateAndParseClaims_returnsCorrectSubject() {
        String token = jwtService.generateAccessToken(testUser);
        Claims claims = jwtService.validateAndParseClaims(token);
        assertThat(claims.getSubject()).isEqualTo(testUser.getId().toString());
    }

    @Test
    void validateAndParseClaims_returnsCorrectEmail() {
        String token = jwtService.generateAccessToken(testUser);
        Claims claims = jwtService.validateAndParseClaims(token);
        assertThat(claims.get("email", String.class)).isEqualTo("jane@example.com");
    }

    @Test
    void validateAndParseClaims_returnsCorrectRoles() {
        String token = jwtService.generateAccessToken(testUser);
        Claims claims = jwtService.validateAndParseClaims(token);
        List<?> roles = claims.get("roles", List.class);
        assertThat(roles).containsExactly("DEVELOPER");
    }

    @Test
    void validateAndParseClaims_throwsOnTamperedToken() {
        String token = jwtService.generateAccessToken(testUser);
        String tampered = token.substring(0, token.lastIndexOf('.') + 1) + "invalidsignature";
        assertThatThrownBy(() -> jwtService.validateAndParseClaims(tampered))
            .isInstanceOf(Exception.class);
    }

    @Test
    void generateAccessToken_withExpiredService_throwsOnValidation() throws Exception {
        KeyPairGenerator generator = KeyPairGenerator.getInstance("RSA");
        generator.initialize(2048);
        KeyPair keyPair = generator.generateKeyPair();

        // expiry of -1 second = already expired
        JwtService expiredService = new JwtService(
            (RSAPrivateKey) keyPair.getPrivate(),
            (RSAPublicKey) keyPair.getPublic(),
            -1L
        );
        String token = expiredService.generateAccessToken(testUser);
        assertThatThrownBy(() -> expiredService.validateAndParseClaims(token))
            .isInstanceOf(ExpiredJwtException.class);
    }
}
