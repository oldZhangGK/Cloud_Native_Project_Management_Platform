package com.pm.auth.controller;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.pm.auth.domain.RoleName;
import com.pm.auth.dto.request.UpdateProfileRequest;
import com.pm.auth.dto.response.UserResponse;
import com.pm.auth.service.JwtService;
import com.pm.auth.service.UserService;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.autoconfigure.web.servlet.WebMvcTest;
import org.springframework.boot.test.mock.mockito.MockBean;
import org.springframework.data.domain.PageImpl;
import org.springframework.http.MediaType;
import org.springframework.test.web.servlet.MockMvc;

import java.time.Instant;
import java.util.List;
import java.util.Set;
import java.util.UUID;

import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.authority.AuthorityUtils;
import org.springframework.test.web.servlet.request.RequestPostProcessor;

import static org.mockito.ArgumentMatchers.*;
import static org.mockito.Mockito.when;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.*;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.*;

// Security enforcement (401/403) is tested in AuthIntegrationTest.
// These tests verify HTTP mapping, request binding, and response shape.
// addFilters=false bypasses Spring Security filter chain so we use .with(user(...))
// to set authentication directly on the request.
@WebMvcTest(UserController.class)
@AutoConfigureMockMvc(addFilters = false)
class UserControllerTest {

    @Autowired MockMvc mockMvc;
    @Autowired ObjectMapper objectMapper;

    @MockBean UserService userService;
    @MockBean JwtService jwtService;

    private static final String USER_UUID = "00000000-0000-0000-0000-000000000001";
    private static final UUID USER_ID = UUID.fromString(USER_UUID);

    private UserResponse sampleUser() {
        return new UserResponse(USER_ID, "jane@example.com", "Jane", "Doe",
            null, Set.of(RoleName.DEVELOPER), Instant.now(), Instant.now());
    }

    // addFilters=false disables SecurityContextHolderFilter so session-based auth post-processors
    // don't propagate. Set userPrincipal directly on the mock request so Spring MVC's
    // PrincipalMethodArgumentResolver can resolve Authentication in controller parameters.
    private static RequestPostProcessor asUser(String userId) {
        return request -> {
            request.setUserPrincipal(new UsernamePasswordAuthenticationToken(
                userId, null, AuthorityUtils.createAuthorityList("ROLE_USER")));
            return request;
        };
    }

    private static RequestPostProcessor asAdmin(String adminId) {
        return request -> {
            request.setUserPrincipal(new UsernamePasswordAuthenticationToken(
                adminId, null, AuthorityUtils.createAuthorityList("ROLE_SYSTEM_ADMIN")));
            return request;
        };
    }

    @Test
    void getMe_returnsCurrentUserProfile() throws Exception {
        when(userService.getUser(USER_ID)).thenReturn(sampleUser());

        mockMvc.perform(get("/api/v1/users/me").with(asUser(USER_UUID)))
            .andExpect(status().isOk())
            .andExpect(jsonPath("$.email").value("jane@example.com"))
            .andExpect(jsonPath("$.id").value(USER_UUID));
    }

    @Test
    void updateMe_withValidRequest_returns200() throws Exception {
        UserResponse updated = new UserResponse(USER_ID, "jane@example.com", "Jane", "Smith",
            null, Set.of(RoleName.DEVELOPER), Instant.now(), Instant.now());
        when(userService.updateProfile(eq(USER_ID), any(UpdateProfileRequest.class))).thenReturn(updated);

        mockMvc.perform(put("/api/v1/users/me")
                .with(asUser(USER_UUID))
                .contentType(MediaType.APPLICATION_JSON)
                .content(objectMapper.writeValueAsString(new UpdateProfileRequest("Jane", "Smith"))))
            .andExpect(status().isOk())
            .andExpect(jsonPath("$.lastName").value("Smith"));
    }

    @Test
    void listUsers_asAdmin_returnsPagedResults() throws Exception {
        when(userService.listUsers(any())).thenReturn(new PageImpl<>(List.of()));

        mockMvc.perform(get("/api/v1/users").with(asAdmin("admin-id")))
            .andExpect(status().isOk());
    }

    @Test
    void getUserById_returnsUser() throws Exception {
        when(userService.getUserById(USER_ID)).thenReturn(sampleUser());

        mockMvc.perform(get("/api/v1/users/{id}", USER_UUID).with(asAdmin("admin-id")))
            .andExpect(status().isOk())
            .andExpect(jsonPath("$.email").value("jane@example.com"));
    }
}
