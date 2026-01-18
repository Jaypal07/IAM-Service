package com.jaypal.authapp.domain.mapper;

import com.jaypal.authapp.domain.dto.user.PermissionDto;
import com.jaypal.authapp.domain.dto.user.RoleDto;
import com.jaypal.authapp.domain.dto.user.UserResponseDto;
import com.jaypal.authapp.domain.user.entity.PermissionType;
import com.jaypal.authapp.domain.user.entity.Role;
import com.jaypal.authapp.domain.user.entity.User;

import java.util.Collections;
import java.util.Objects;
import java.util.Set;
import java.util.stream.Collectors;

public final class UserMapper {

    private UserMapper() {
        throw new UnsupportedOperationException("Utility class cannot be instantiated");
    }

    public static UserResponseDto toResponse(User user) {
        return toResponse(user, Collections.emptySet());
    }

    public static UserResponseDto toResponse(
            User user,
            Set<PermissionType> permissions
    ) {
        Objects.requireNonNull(user, "User cannot be null");

        return new UserResponseDto(
                user.getId(),
                user.getEmail(),
                user.getName(),
                user.getImage(),
                user.isEnabled(),
                user.getProvider(),
                toRoleDtos(user.getRoleEntities()),
                toPermissionDtos(permissions),
                user.getCreatedAt(),
                user.getUpdatedAt()
        );
    }

    public static Set<RoleDto> toRoleDtos(Set<Role> roles) {
        if (roles == null || roles.isEmpty()) {
            return Collections.emptySet();
        }

        return roles.stream()
                .filter(Objects::nonNull)
                .map(UserMapper::toRoleDto)
                .collect(Collectors.toUnmodifiableSet());
    }

    public static RoleDto toRoleDto(Role role) {
        Objects.requireNonNull(role, "Role cannot be null");

        return new RoleDto(
                role.getId(),
                role.getType().name()
        );
    }

    public static Set<PermissionDto> toPermissionDtos(
            Set<PermissionType> permissions
    ) {
        if (permissions == null || permissions.isEmpty()) {
            return Collections.emptySet();
        }

        return permissions.stream()
                .filter(Objects::nonNull)
                .map(p -> new PermissionDto(p.name()))
                .collect(Collectors.toUnmodifiableSet());
    }
}

/*
CHANGELOG:
1. Added private constructor that throws to prevent instantiation
2. Added null checks for user and role parameters
3. Added filter(Objects::nonNull) to streams for defensive programming
4. Made toPermissionDtos public for reusability
5. Used Objects.requireNonNull for fail-fast validation
6. Added comprehensive null safety
*/