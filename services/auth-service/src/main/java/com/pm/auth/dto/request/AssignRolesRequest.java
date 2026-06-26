package com.pm.auth.dto.request;

import com.pm.auth.domain.RoleName;
import jakarta.validation.constraints.NotNull;

import java.util.Set;

public record AssignRolesRequest(
    @NotNull(message = "Roles must not be null")
    Set<RoleName> roles
) {}
