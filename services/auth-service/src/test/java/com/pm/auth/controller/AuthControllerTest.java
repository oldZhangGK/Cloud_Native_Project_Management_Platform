package com.pm.auth.controller;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.pm.auth.domain.RoleName;
import com.pm.auth.dto.request.*;
import com.pm.auth.dto.response.AuthResponse;
import com.pm.auth.dto.response.UserResponse;
import com.pm.auth.service.AuthService;
import com.pm.auth.service.JwtService;
import com.pm.auth.service.PasswordResetService;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.autoconfigure.web.servlet.WebMvcTest;
import org.springframework.boot.test.mock.mockito.MockBean;
import org.springframework.http.MediaType;
import org.springframework.test.web.servlet.MockMvc;

import java.time.Instant;
import java.util.Set;
import java.util.UUID;

import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.*;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.*;

// Security (who can call what) is tested in AuthIntegrationTest.
// These tests focus only on request mapping, input validation, and response shape.
@WebMvcTest(AuthController.class)
@AutoConfigureMockMvc(addFilters = false)
class AuthControllerTest {

    @Autowired MockMvc mockMvc;
    @Autowired ObjectMapper objectMapper;

    @MockBean AuthService authService;
    @MockBean PasswordResetService passwordResetService;
    @MockBean JwtService jwtService;   // required by JwtAuthenticationFilter for context startup

    private static final UUID USER_ID = UUID.randomUUID();

    @Test
    void register_withValidRequest_returns201() throws Exception {
        UserResponse response = new UserResponse(USER_ID, "jane@example.com",
            "Jane", "Doe", null, Set.of(RoleName.DEVELOPER), Instant.now(), Instant.now());
        when(authService.register(any(RegisterRequest.class))).thenReturn(response);

        mockMvc.perform(post("/api/v1/auth/register")
                .contentType(MediaType.APPLICATION_JSON)
                .content(objectMapper.writeValueAsString(
                    new RegisterRequest("jane@example.com", "SecurePass1!", "Jane", "Doe"))))
            .andExpect(status().isCreated())
            .andExpect(jsonPath("$.email").value("jane@example.com"));
    }

    @Test
    void register_withInvalidEmail_returns400() throws Exception {
        mockMvc.perform(post("/api/v1/auth/register")
                .contentType(MediaType.APPLICATION_JSON)
                .content(objectMapper.writeValueAsString(
                    new RegisterRequest("not-an-email", "SecurePass1!", "Jane", "Doe"))))
            .andExpect(status().isBadRequest())
            .andExpect(jsonPath("$.code").value("VALIDATION_ERROR"));
    }

    @Test
    void register_withWeakPassword_returns400() throws Exception {
        mockMvc.perform(post("/api/v1/auth/register")
                .contentType(MediaType.APPLICATION_JSON)
                .content(objectMapper.writeValueAsString(
                    new RegisterRequest("jane@example.com", "weak", "Jane", "Doe"))))
            .andExpect(status().isBadRequest());
    }

    @Test
    void login_withValidRequest_returns200() throws Exception {
        AuthResponse response = AuthResponse.of("access.token", "refresh.token", 900L);
        when(authService.login(any(LoginRequest.class))).thenReturn(response);

        mockMvc.perform(post("/api/v1/auth/login")
                .contentType(MediaType.APPLICATION_JSON)
                .content(objectMapper.writeValueAsString(
                    new LoginRequest("jane@example.com", "SecurePass1!"))))
            .andExpect(status().isOk())
            .andExpect(jsonPath("$.accessToken").value("access.token"))
            .andExpect(jsonPath("$.tokenType").value("Bearer"))
            .andExpect(jsonPath("$.expiresIn").value(900));
    }

    @Test
    void refresh_withValidToken_returns200() throws Exception {
        AuthResponse response = AuthResponse.of("new.access.token", "new.refresh.token", 900L);
        when(authService.refresh(any(RefreshTokenRequest.class))).thenReturn(response);

        mockMvc.perform(post("/api/v1/auth/refresh")
                .contentType(MediaType.APPLICATION_JSON)
                .content(objectMapper.writeValueAsString(new RefreshTokenRequest("old-refresh-token"))))
            .andExpect(status().isOk())
            .andExpect(jsonPath("$.accessToken").value("new.access.token"));
    }

    @Test
    void logout_returns204() throws Exception {
        doNothing().when(authService).logout(any(LogoutRequest.class));

        mockMvc.perform(post("/api/v1/auth/logout")
                .contentType(MediaType.APPLICATION_JSON)
                .content(objectMapper.writeValueAsString(new LogoutRequest("refresh-token"))))
            .andExpect(status().isNoContent());
    }

    @Test
    void resetRequest_returns200WithGenericMessage() throws Exception {
        when(passwordResetService.requestReset("jane@example.com"))
            .thenReturn(new PasswordResetService.ResetRequestResult(
                "If an account exists with that email, a reset link has been sent.", "raw-token"));

        mockMvc.perform(post("/api/v1/auth/password/reset-request")
                .contentType(MediaType.APPLICATION_JSON)
                .content(objectMapper.writeValueAsString(new PasswordResetRequestDto("jane@example.com"))))
            .andExpect(status().isOk())
            .andExpect(jsonPath("$.message").exists())
            .andExpect(jsonPath("$.resetToken").value("raw-token"));
    }

    @Test
    void resetConfirm_withValidRequest_returns200() throws Exception {
        doNothing().when(passwordResetService).confirmReset(any(), any());

        mockMvc.perform(post("/api/v1/auth/password/reset")
                .contentType(MediaType.APPLICATION_JSON)
                .content(objectMapper.writeValueAsString(
                    new PasswordResetConfirmRequest("raw-reset-token", "NewSecurePass1!"))))
            .andExpect(status().isOk())
            .andExpect(jsonPath("$.message").value("Password has been reset successfully."));
    }
}
