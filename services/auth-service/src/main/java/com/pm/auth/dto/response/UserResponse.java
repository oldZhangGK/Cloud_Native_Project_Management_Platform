package com.pm.auth.dto.response;

import com.pm.auth.domain.RoleName;
import com.pm.auth.domain.User;

import java.time.Instant;
import java.util.Set;
import java.util.UUID;
import java.util.stream.Collectors;

public record UserResponse(
    UUID id,
    String email,
    String firstName,
    String lastName,
    String avatarUrl,
    Set<RoleName> roles,
    Instant createdAt,
    Instant updatedAt
) {
    public static UserResponse from(User user) {
        return new UserResponse(
            user.getId(),
            user.getEmail(),
            user.getFirstName(),
            user.getLastName(),
            user.getAvatarUrl(),
            user.getRoles().stream().map(r -> r.getName()).collect(Collectors.toSet()),
            user.getCreatedAt(),
            user.getUpdatedAt()
        );
    }
}
