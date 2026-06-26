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
import com.pm.auth.event.UserEventPublisher;
import com.pm.auth.repository.RoleRepository;
import com.pm.auth.repository.UserRepository;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.security.crypto.password.PasswordEncoder;

import java.util.Optional;
import java.util.UUID;

import static org.assertj.core.api.Assertions.*;
import static org.mockito.ArgumentMatchers.*;
import static org.mockito.Mockito.*;

@ExtendWith(MockitoExtension.class)
class AuthServiceTest {

    @Mock private UserRepository userRepository;
    @Mock private RoleRepository roleRepository;
    @Mock private PasswordEncoder passwordEncoder;
    @Mock private JwtService jwtService;
    @Mock private RefreshTokenService refreshTokenService;
    @Mock private UserEventPublisher userEventPublisher;

    @InjectMocks
    private AuthService authService;

    private Role developerRole;

    @BeforeEach
    void setUp() {
        developerRole = new Role(RoleName.DEVELOPER, "Standard contributor");
        developerRole.setId(UUID.randomUUID());
    }

    // --- register ---

    @Test
    void register_withNewEmail_createsUser() {
        RegisterRequest request = new RegisterRequest(
            "jane@example.com", "SecurePass1!", "Jane", "Doe"
        );
        when(userRepository.existsByEmail("jane@example.com")).thenReturn(false);
        when(roleRepository.findByName(RoleName.DEVELOPER)).thenReturn(Optional.of(developerRole));
        when(userRepository.save(any(User.class))).thenAnswer(inv -> {
            User u = inv.getArgument(0);
            u.setId(UUID.randomUUID());
            return u;
        });

        UserResponse response = authService.register(request);

        assertThat(response.email()).isEqualTo("jane@example.com");
        assertThat(response.roles()).contains(RoleName.DEVELOPER);
        verify(userRepository).save(any(User.class));
    }

    @Test
    void register_withExistingEmail_throwsUserAlreadyExistsException() {
        RegisterRequest request = new RegisterRequest(
            "jane@example.com", "SecurePass1!", "Jane", "Doe"
        );
        when(userRepository.existsByEmail("jane@example.com")).thenReturn(true);

        assertThatThrownBy(() -> authService.register(request))
            .isInstanceOf(UserAlreadyExistsException.class);

        verify(userRepository, never()).save(any());
    }

    @Test
    void register_normalisesEmailToLowercase() {
        RegisterRequest request = new RegisterRequest(
            "JANE@EXAMPLE.COM", "SecurePass1!", "Jane", "Doe"
        );
        when(userRepository.existsByEmail("jane@example.com")).thenReturn(false);
        when(roleRepository.findByName(RoleName.DEVELOPER)).thenReturn(Optional.of(developerRole));
        when(userRepository.save(any(User.class))).thenAnswer(inv -> {
            User u = inv.getArgument(0);
            u.setId(UUID.randomUUID());
            return u;
        });

        UserResponse response = authService.register(request);
        assertThat(response.email()).isEqualTo("jane@example.com");
    }

    // --- login ---

    @Test
    void login_withValidCredentials_returnsAuthResponse() {
        User user = buildUser(true);
        LoginRequest request = new LoginRequest("jane@example.com", "SecurePass1!");

        when(userRepository.findByEmail("jane@example.com")).thenReturn(Optional.of(user));
        when(passwordEncoder.matches("SecurePass1!", user.getPasswordHash())).thenReturn(true);
        when(jwtService.generateAccessToken(user)).thenReturn("access.token.here");
        when(jwtService.getAccessTokenExpirySeconds()).thenReturn(900L);
        when(refreshTokenService.issueToken(any(UUID.class), any(UUID.class))).thenReturn("refresh.token.here");

        AuthResponse response = authService.login(request);

        assertThat(response.accessToken()).isEqualTo("access.token.here");
        assertThat(response.tokenType()).isEqualTo("Bearer");
        assertThat(response.expiresIn()).isEqualTo(900L);
    }

    @Test
    void login_withUnknownEmail_throwsInvalidCredentialsException() {
        when(userRepository.findByEmail(anyString())).thenReturn(Optional.empty());

        assertThatThrownBy(() -> authService.login(new LoginRequest("x@x.com", "pass")))
            .isInstanceOf(InvalidCredentialsException.class);
    }

    @Test
    void login_withWrongPassword_throwsInvalidCredentialsException() {
        User user = buildUser(true);
        when(userRepository.findByEmail("jane@example.com")).thenReturn(Optional.of(user));
        when(passwordEncoder.matches(anyString(), anyString())).thenReturn(false);

        assertThatThrownBy(() -> authService.login(new LoginRequest("jane@example.com", "wrong")))
            .isInstanceOf(InvalidCredentialsException.class);
    }

    @Test
    void login_withDeactivatedAccount_throwsAccountDisabledException() {
        User user = buildUser(false);
        when(userRepository.findByEmail("jane@example.com")).thenReturn(Optional.of(user));

        assertThatThrownBy(() -> authService.login(new LoginRequest("jane@example.com", "any")))
            .isInstanceOf(AccountDisabledException.class);
    }

    private User buildUser(boolean active) {
        User user = new User();
        user.setId(UUID.randomUUID());
        user.setEmail("jane@example.com");
        user.setPasswordHash("hashed");
        user.setFirstName("Jane");
        user.setLastName("Doe");
        user.setActive(active);
        user.getRoles().add(developerRole);
        return user;
    }
}
