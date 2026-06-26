package com.pm.auth.integration;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.pm.auth.dto.request.*;
import com.pm.auth.dto.response.AuthResponse;
import com.pm.auth.dto.response.UserResponse;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.http.MediaType;
import org.springframework.kafka.test.context.EmbeddedKafka;
import org.springframework.test.annotation.DirtiesContext;
import org.springframework.test.context.DynamicPropertyRegistry;
import org.springframework.test.context.DynamicPropertySource;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.MvcResult;
import org.testcontainers.containers.PostgreSQLContainer;
import org.testcontainers.junit.jupiter.Container;
import org.testcontainers.junit.jupiter.Testcontainers;

import static org.assertj.core.api.Assertions.assertThat;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.*;

@SpringBootTest
@AutoConfigureMockMvc
@Testcontainers
@DirtiesContext
@EmbeddedKafka(partitions = 1,
               bootstrapServersProperty = "spring.kafka.bootstrap-servers",
               topics = {"user.events"})
class AuthIntegrationTest {

    @Container
    static PostgreSQLContainer<?> postgres = new PostgreSQLContainer<>("postgres:16")
        .withDatabaseName("pm_db")
        .withUsername("pm_user")
        .withPassword("pm_password");

    @DynamicPropertySource
    static void dbProperties(DynamicPropertyRegistry registry) {
        registry.add("spring.datasource.url", postgres::getJdbcUrl);
        registry.add("spring.datasource.username", postgres::getUsername);
        registry.add("spring.datasource.password", postgres::getPassword);
    }

    @Autowired MockMvc mockMvc;
    @Autowired ObjectMapper objectMapper;

    // ---- helpers ----

    private UserResponse register(String email, String password) throws Exception {
        MvcResult result = mockMvc.perform(post("/api/v1/auth/register")
                .contentType(MediaType.APPLICATION_JSON)
                .content(objectMapper.writeValueAsString(
                    new RegisterRequest(email, password, "Test", "User"))))
            .andExpect(status().isCreated())
            .andReturn();
        return objectMapper.readValue(result.getResponse().getContentAsString(), UserResponse.class);
    }

    private AuthResponse login(String email, String password) throws Exception {
        MvcResult result = mockMvc.perform(post("/api/v1/auth/login")
                .contentType(MediaType.APPLICATION_JSON)
                .content(objectMapper.writeValueAsString(new LoginRequest(email, password))))
            .andExpect(status().isOk())
            .andReturn();
        return objectMapper.readValue(result.getResponse().getContentAsString(), AuthResponse.class);
    }

    // ---- tests ----

    @Test
    void registerAndLogin_fullFlow() throws Exception {
        UserResponse user = register("it-user1@example.com", "SecurePass1!");

        assertThat(user.email()).isEqualTo("it-user1@example.com");
        assertThat(user.id()).isNotNull();

        AuthResponse tokens = login("it-user1@example.com", "SecurePass1!");
        assertThat(tokens.accessToken()).isNotBlank();
        assertThat(tokens.refreshToken()).isNotBlank();
        assertThat(tokens.tokenType()).isEqualTo("Bearer");
        assertThat(tokens.expiresIn()).isEqualTo(900L);
    }

    @Test
    void refresh_withValidToken_returnsNewTokenPair() throws Exception {
        register("it-user2@example.com", "SecurePass1!");
        AuthResponse initial = login("it-user2@example.com", "SecurePass1!");

        MvcResult refreshResult = mockMvc.perform(post("/api/v1/auth/refresh")
                .contentType(MediaType.APPLICATION_JSON)
                .content(objectMapper.writeValueAsString(
                    new RefreshTokenRequest(initial.refreshToken()))))
            .andExpect(status().isOk())
            .andReturn();

        AuthResponse rotated = objectMapper.readValue(
            refreshResult.getResponse().getContentAsString(), AuthResponse.class);

        assertThat(rotated.accessToken()).isNotBlank().isNotEqualTo(initial.accessToken());
        assertThat(rotated.refreshToken()).isNotBlank().isNotEqualTo(initial.refreshToken());
    }

    @Test
    void refresh_reusingOldToken_returns401TokenReuseDetected() throws Exception {
        register("it-user3@example.com", "SecurePass1!");
        AuthResponse initial = login("it-user3@example.com", "SecurePass1!");

        // Rotate once — old token is now revoked
        mockMvc.perform(post("/api/v1/auth/refresh")
                .contentType(MediaType.APPLICATION_JSON)
                .content(objectMapper.writeValueAsString(
                    new RefreshTokenRequest(initial.refreshToken()))))
            .andExpect(status().isOk());

        // Replaying the original token should trigger reuse detection
        mockMvc.perform(post("/api/v1/auth/refresh")
                .contentType(MediaType.APPLICATION_JSON)
                .content(objectMapper.writeValueAsString(
                    new RefreshTokenRequest(initial.refreshToken()))))
            .andExpect(status().isUnauthorized())
            .andExpect(jsonPath("$.code").value("TOKEN_REUSE_DETECTED"));
    }

    @Test
    void logout_revokesRefreshToken() throws Exception {
        register("it-user4@example.com", "SecurePass1!");
        AuthResponse tokens = login("it-user4@example.com", "SecurePass1!");

        // Logout
        mockMvc.perform(post("/api/v1/auth/logout")
                .header("Authorization", "Bearer " + tokens.accessToken())
                .contentType(MediaType.APPLICATION_JSON)
                .content(objectMapper.writeValueAsString(new LogoutRequest(tokens.refreshToken()))))
            .andExpect(status().isNoContent());

        // Using the revoked refresh token should now fail
        mockMvc.perform(post("/api/v1/auth/refresh")
                .contentType(MediaType.APPLICATION_JSON)
                .content(objectMapper.writeValueAsString(
                    new RefreshTokenRequest(tokens.refreshToken()))))
            .andExpect(status().isUnauthorized());
    }

    @Test
    void usersMe_withValidAccessToken_returnsUserProfile() throws Exception {
        register("it-user5@example.com", "SecurePass1!");
        AuthResponse tokens = login("it-user5@example.com", "SecurePass1!");

        mockMvc.perform(get("/api/v1/users/me")
                .header("Authorization", "Bearer " + tokens.accessToken()))
            .andExpect(status().isOk())
            .andExpect(jsonPath("$.email").value("it-user5@example.com"));
    }

    @Test
    void usersMe_withoutToken_returns401() throws Exception {
        mockMvc.perform(get("/api/v1/users/me"))
            .andExpect(status().isUnauthorized());
    }

    @Test
    void passwordReset_fullFlow() throws Exception {
        register("it-user6@example.com", "SecurePass1!");
        AuthResponse oldTokens = login("it-user6@example.com", "SecurePass1!");

        // Request reset
        MvcResult resetReqResult = mockMvc.perform(post("/api/v1/auth/password/reset-request")
                .contentType(MediaType.APPLICATION_JSON)
                .content(objectMapper.writeValueAsString(
                    new PasswordResetRequestDto("it-user6@example.com"))))
            .andExpect(status().isOk())
            .andReturn();

        @SuppressWarnings("unchecked")
        java.util.Map<String, String> resetBody = objectMapper.readValue(
            resetReqResult.getResponse().getContentAsString(), java.util.Map.class);
        String resetToken = resetBody.get("resetToken");
        assertThat(resetToken).isNotBlank();

        // Confirm reset
        mockMvc.perform(post("/api/v1/auth/password/reset")
                .contentType(MediaType.APPLICATION_JSON)
                .content(objectMapper.writeValueAsString(
                    new PasswordResetConfirmRequest(resetToken, "NewSecurePass2@"))))
            .andExpect(status().isOk())
            .andExpect(jsonPath("$.message").value("Password has been reset successfully."));

        // Old refresh token should be revoked
        mockMvc.perform(post("/api/v1/auth/refresh")
                .contentType(MediaType.APPLICATION_JSON)
                .content(objectMapper.writeValueAsString(
                    new RefreshTokenRequest(oldTokens.refreshToken()))))
            .andExpect(status().isUnauthorized());

        // Should be able to login with new password
        AuthResponse newTokens = login("it-user6@example.com", "NewSecurePass2@");
        assertThat(newTokens.accessToken()).isNotBlank();
    }

    @Test
    void jwks_returnsPublicKey() throws Exception {
        mockMvc.perform(get("/api/v1/auth/keys"))
            .andExpect(status().isOk())
            .andExpect(jsonPath("$.keys[0].kty").value("RSA"))
            .andExpect(jsonPath("$.keys[0].alg").value("RS256"))
            .andExpect(jsonPath("$.keys[0].n").isNotEmpty())
            .andExpect(jsonPath("$.keys[0].e").isNotEmpty());
    }
}
