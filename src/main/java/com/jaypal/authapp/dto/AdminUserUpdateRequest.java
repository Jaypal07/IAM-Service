package com.jaypal.authapp.dto;

import java.util.Set;

public record AdminUserUpdateRequest(
        String name,
        String image,
        boolean enabled,
        Set<RoleDto> roles
) {}
