package com.jaypal.authapp.user.dto;

import com.jaypal.authapp.user.model.Provider;
import lombok.Builder;

import java.time.Instant;
import java.util.Set;
import java.util.UUID;

@Builder
public record UserResponseDto(
        UUID id,
        String email,
        String name,
        String image,
        boolean enabled,
        Provider provider,
        Set<RoleDto> roles,
        Set<PermissionDto> permissions,
        Instant createdAt,
        Instant updatedAt
) {}
