package com.jaypal.authapp.user.dto;

import java.util.Set;

public record AdminUserRoleUpdateRequest(
        Set<String> addRoles,
        Set<String> removeRoles
) {}
