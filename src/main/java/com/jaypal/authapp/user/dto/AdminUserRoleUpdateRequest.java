package com.jaypal.authapp.user.dto;

import jakarta.validation.constraints.Pattern;

import java.util.Set;

public record AdminUserRoleUpdateRequest(

        Set<@Pattern(
                regexp = "ROLE_(USER|ADMIN)",
                message = "Invalid role name. Must be ROLE_USER or ROLE_OWNER"
        ) String> addRoles,

        Set<@Pattern(
                regexp = "ROLE_(USER|ADMIN)",
                message = "Invalid role name. Must be ROLE_USER or ROLE_ADMIN"
        ) String> removeRoles
) {
    public AdminUserRoleUpdateRequest {
        if ((addRoles == null || addRoles.isEmpty()) &&
                (removeRoles == null || removeRoles.isEmpty())) {
            throw new IllegalArgumentException("At least one role operation required");
        }
    }
}