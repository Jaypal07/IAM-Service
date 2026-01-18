package com.jaypal.authapp.domain.dto.user;

import com.jaypal.authapp.domain.user.entity.Provider;
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
