package com.jaypal.authapp.user.application;

import com.jaypal.authapp.user.model.PermissionType;
import com.jaypal.authapp.user.repository.PermissionRepository;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.cache.annotation.Cacheable;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.util.Objects;
import java.util.Set;
import java.util.UUID;
import java.util.stream.Collectors;

@Slf4j
@Service
@RequiredArgsConstructor
public class PermissionService {

    private final PermissionRepository permissionRepository;

    @Cacheable(
            cacheNames = "userPermissions",
            key = "#userId",
            unless = "#result == null || #result.isEmpty()"
    )
    @Transactional(readOnly = true)
    public Set<PermissionType> resolvePermissions(UUID userId) {
        Objects.requireNonNull(userId, "User ID cannot be null");

        Set<PermissionType> permissions =
                permissionRepository.findPermissionTypesByUserId(userId);

        log.debug("Resolved {} permissions for user {}", permissions.size(), userId);

        return permissions;
    }

    /**
     * Deterministic permission fingerprint.
     * Used for debugging, audits, and token validation.
     */
    public String permissionHash(Set<PermissionType> permissions) {
        Objects.requireNonNull(permissions, "Permissions cannot be null");

        if (permissions.isEmpty()) {
            return "";
        }

        return permissions.stream()
                .map(Enum::name)
                .sorted()
                .collect(Collectors.joining("|"));
    }
}
