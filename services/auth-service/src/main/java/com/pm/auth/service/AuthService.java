package com.pm.auth.service;

import com.pm.auth.domain.Role;
import com.pm.auth.domain.RoleName;
import com.pm.auth.domain.User;
import com.pm.auth.dto.request.LoginRequest;
import com.pm.auth.dto.request.LogoutRequest;
import com.pm.auth.dto.request.RefreshTokenRequest;
import com.pm.auth.dto.request.RegisterRequest;
import com.pm.auth.dto.response.AuthResponse;
import com.pm.auth.dto.response.UserResponse;
import com.pm.auth.event.UserEventPublisher;
import com.pm.auth.exception.AccountDisabledException;
import com.pm.auth.exception.InvalidCredentialsException;
import com.pm.auth.exception.UserAlreadyExistsException;
import com.pm.auth.repository.RoleRepository;
import com.pm.auth.repository.UserRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.util.UUID;

@Service
@RequiredArgsConstructor
public class AuthService {

    private final UserRepository userRepository;
    private final RoleRepository roleRepository;
    private final PasswordEncoder passwordEncoder;
    private final JwtService jwtService;
    private final RefreshTokenService refreshTokenService;
    private final UserEventPublisher userEventPublisher;

    @Transactional
    public UserResponse register(RegisterRequest request) {
        String normalizedEmail = request.email().toLowerCase().trim();

        if (userRepository.existsByEmail(normalizedEmail)) {
            throw new UserAlreadyExistsException(normalizedEmail);
        }

        Role defaultRole = roleRepository.findByName(RoleName.DEVELOPER)
            .orElseThrow(() -> new IllegalStateException("Default role DEVELOPER not found — check seed data"));

        User user = new User();
        user.setEmail(normalizedEmail);
        user.setPasswordHash(passwordEncoder.encode(request.password()));
        user.setFirstName(request.firstName().trim());
        user.setLastName(request.lastName().trim());
        user.getRoles().add(defaultRole);

        User saved = userRepository.save(user);
        userEventPublisher.publishUserRegistered(saved);
        return UserResponse.from(saved);
    }

    @Transactional
    public AuthResponse login(LoginRequest request) {
        User user = userRepository.findByEmail(request.email().toLowerCase().trim())
            .orElseThrow(InvalidCredentialsException::new);

        if (!user.isActive()) {
            throw new AccountDisabledException();
        }

        if (!passwordEncoder.matches(request.password(), user.getPasswordHash())) {
            throw new InvalidCredentialsException();
        }

        String accessToken = jwtService.generateAccessToken(user);
        UUID familyId = UUID.randomUUID();
        String refreshToken = refreshTokenService.issueToken(user.getId(), familyId);

        return AuthResponse.of(accessToken, refreshToken, jwtService.getAccessTokenExpirySeconds());
    }

    @Transactional
    public AuthResponse refresh(RefreshTokenRequest request) {
        RefreshTokenService.RotateResult rotated = refreshTokenService.rotate(request.refreshToken());

        User user = userRepository.findById(rotated.userId())
            .orElseThrow(() -> new IllegalStateException("User not found after token rotation"));

        String newAccessToken = jwtService.generateAccessToken(user);
        return AuthResponse.of(newAccessToken, rotated.newRawToken(), jwtService.getAccessTokenExpirySeconds());
    }

    @Transactional
    public void logout(LogoutRequest request) {
        refreshTokenService.revokeToken(request.refreshToken());
    }
}
