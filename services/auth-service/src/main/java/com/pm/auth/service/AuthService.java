package com.pm.auth.service;

import com.pm.auth.domain.Role;
import com.pm.auth.domain.RoleName;
import com.pm.auth.domain.User;
import com.pm.auth.dto.request.LoginRequest;
import com.pm.auth.dto.request.RegisterRequest;
import com.pm.auth.dto.response.AuthResponse;
import com.pm.auth.dto.response.UserResponse;
import com.pm.auth.exception.AccountDisabledException;
import com.pm.auth.exception.InvalidCredentialsException;
import com.pm.auth.exception.UserAlreadyExistsException;
import com.pm.auth.repository.RoleRepository;
import com.pm.auth.repository.UserRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

@Service
@RequiredArgsConstructor
public class AuthService {

    private final UserRepository userRepository;
    private final RoleRepository roleRepository;
    private final PasswordEncoder passwordEncoder;
    private final JwtService jwtService;

    @Transactional
    public UserResponse register(RegisterRequest request) {
        if (userRepository.existsByEmail(request.email())) {
            throw new UserAlreadyExistsException(request.email());
        }

        Role defaultRole = roleRepository.findByName(RoleName.DEVELOPER)
            .orElseThrow(() -> new IllegalStateException("Default role DEVELOPER not found — check seed data"));

        User user = new User();
        user.setEmail(request.email().toLowerCase().trim());
        user.setPasswordHash(passwordEncoder.encode(request.password()));
        user.setFirstName(request.firstName().trim());
        user.setLastName(request.lastName().trim());
        user.getRoles().add(defaultRole);

        User saved = userRepository.save(user);
        return UserResponse.from(saved);
    }

    @Transactional(readOnly = true)
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

        // Refresh token logic is Sprint 2 — placeholder token for Sprint 1
        String refreshToken = "SPRINT_2_PLACEHOLDER";

        return AuthResponse.of(accessToken, refreshToken, jwtService.getAccessTokenExpirySeconds());
    }
}
