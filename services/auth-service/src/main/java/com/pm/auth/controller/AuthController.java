package com.pm.auth.controller;

import com.pm.auth.dto.request.*;
import com.pm.auth.dto.response.AuthResponse;
import com.pm.auth.dto.response.MessageResponse;
import com.pm.auth.dto.response.UserResponse;
import com.pm.auth.service.AuthService;
import com.pm.auth.service.PasswordResetService;
import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.tags.Tag;
import jakarta.validation.Valid;
import lombok.RequiredArgsConstructor;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import java.util.LinkedHashMap;
import java.util.Map;

@RestController
@RequestMapping("/api/v1/auth")
@RequiredArgsConstructor
@Tag(name = "Authentication", description = "Register, login, and token management")
public class AuthController {

    private final AuthService authService;
    private final PasswordResetService passwordResetService;

    @PostMapping("/register")
    @Operation(summary = "Register a new user")
    public ResponseEntity<UserResponse> register(@Valid @RequestBody RegisterRequest request) {
        return ResponseEntity.status(HttpStatus.CREATED).body(authService.register(request));
    }

    @PostMapping("/login")
    @Operation(summary = "Login and receive JWT tokens")
    public ResponseEntity<AuthResponse> login(@Valid @RequestBody LoginRequest request) {
        return ResponseEntity.ok(authService.login(request));
    }

    @PostMapping("/refresh")
    @Operation(summary = "Rotate refresh token and receive a new token pair")
    public ResponseEntity<AuthResponse> refresh(@Valid @RequestBody RefreshTokenRequest request) {
        return ResponseEntity.ok(authService.refresh(request));
    }

    @PostMapping("/logout")
    @Operation(summary = "Revoke the current refresh token")
    public ResponseEntity<Void> logout(@Valid @RequestBody LogoutRequest request) {
        authService.logout(request);
        return ResponseEntity.noContent().build();
    }

    @PostMapping("/password/reset-request")
    @Operation(summary = "Request a password reset link")
    public ResponseEntity<Map<String, Object>> resetRequest(
            @Valid @RequestBody PasswordResetRequestDto request) {
        PasswordResetService.ResetRequestResult result =
            passwordResetService.requestReset(request.email());

        // Phase 1: include resetToken in response for local testing
        // Phase 2: remove resetToken field once email delivery is wired in Sprint 8
        Map<String, Object> body = new LinkedHashMap<>();
        body.put("message", result.message());
        if (result.resetToken() != null) {
            body.put("resetToken", result.resetToken());
        }

        return ResponseEntity.ok(body);
    }

    @PostMapping("/password/reset")
    @Operation(summary = "Confirm password reset with token")
    public ResponseEntity<MessageResponse> resetConfirm(
            @Valid @RequestBody PasswordResetConfirmRequest request) {
        passwordResetService.confirmReset(request.token(), request.newPassword());
        return ResponseEntity.ok(MessageResponse.of("Password has been reset successfully."));
    }
}
