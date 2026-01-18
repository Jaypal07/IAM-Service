package com.jaypal.authapp.infrastructure.bootstrap;

import com.jaypal.authapp.domain.user.entity.*;
import com.jaypal.authapp.domain.user.repository.PermissionRepository;
import com.jaypal.authapp.domain.user.repository.RolePermissionRepository;
import com.jaypal.authapp.domain.user.repository.RoleRepository;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.boot.ApplicationArguments;
import org.springframework.boot.ApplicationRunner;
import org.springframework.core.annotation.Order;
import org.springframework.stereotype.Component;
import org.springframework.transaction.annotation.Transactional;

import java.time.Instant;
import java.util.*;
import java.util.stream.Collectors;

@Slf4j
@Component
@RequiredArgsConstructor
@Order(1)
public class PermissionBootstrapRunner implements ApplicationRunner {

    private final RoleRepository roleRepository;
    private final PermissionRepository permissionRepository;
    private final RolePermissionRepository rolePermissionRepository;

    @Override
    @Transactional
    public void run(ApplicationArguments args) {
        log.info("=== IAM Permission Bootstrap Started ===");

        try {
            bootstrapRoles();
            bootstrapPermissions();
            bootstrapRolePermissions();

            log.info("=== IAM Permission Bootstrap Completed Successfully ===");
        } catch (Exception ex) {
            log.error("=== IAM Permission Bootstrap FAILED ===", ex);
            throw new IllegalStateException("IAM bootstrap failed. Application cannot start", ex);
        }
    }

    private void bootstrapRoles() {
        log.info("Bootstrapping roles...");
        final Instant now = Instant.now();
        int created = 0;

        for (RoleType type : RoleType.values()) {
            if (roleRepository.findByType(type).isEmpty()) {
                roleRepository.save(Role.builder()
                        .name(type.name())
                        .type(type)
                        .description(getRoleDescription(type))
                        .immutable(true)
                        .createdAt(now)
                        .build());
                created++;
                log.debug("Created role {}", type);
            }
        }

        log.info("Roles bootstrapped. Created={}, Total={}", created, RoleType.values().length);
    }

    private void bootstrapPermissions() {
        log.info("Bootstrapping permissions...");
        final Instant now = Instant.now();
        int created = 0;

        for (PermissionType type : PermissionType.values()) {
            if (permissionRepository.findByType(type).isEmpty()) {
                permissionRepository.save(Permission.builder()
                        .type(type)
                        .description(getPermissionDescription(type))
                        .createdAt(now)
                        .build());
                created++;
                log.debug("Created permission {}", type);
            }
        }

        log.info("Permissions bootstrapped. Created={}, Total={}", created, PermissionType.values().length);
    }

    private void bootstrapRolePermissions() {
        log.info("Bootstrapping role permission mappings...");

        final Role userRole = requireRole(RoleType.ROLE_USER);
        final Role adminRole = requireRole(RoleType.ROLE_ADMIN);
        final Role ownerRole = requireRole(RoleType.ROLE_OWNER);

        assignPermissions(userRole, EnumSet.of(
                PermissionType.USER_READ
        ));

        assignPermissions(adminRole, EnumSet.of(
                PermissionType.USER_CREATE,
                PermissionType.USER_READ,
                PermissionType.USER_UPDATE,
                PermissionType.USER_DISABLE,
                PermissionType.USER_ROLE_ASSIGN,
                PermissionType.ROLE_READ,
                PermissionType.PERMISSION_READ,
                PermissionType.TOKEN_REVOKE,
                PermissionType.SESSION_TERMINATE,
                PermissionType.AUDIT_READ
        ));

        assignPermissions(ownerRole, EnumSet.allOf(PermissionType.class));

        log.info("Role permission mappings bootstrapped");
    }

    private void assignPermissions(Role role, Set<PermissionType> desiredPermissions) {
        Objects.requireNonNull(role, "Role cannot be null");
        Objects.requireNonNull(desiredPermissions, "Desired permissions cannot be null");

        final Set<PermissionType> existing =
                rolePermissionRepository.findPermissionTypesByRole(role);

        final Set<PermissionType> missing = new HashSet<>(desiredPermissions);
        missing.removeAll(existing);

        if (missing.isEmpty()) {
            log.debug("No new permissions to assign for role {}", role.getType());
            return;
        }

        final Instant now = Instant.now();
        final List<RolePermission> mappings = missing.stream()
                .map(type -> {
                    Permission permission = permissionRepository.findByType(type)
                            .orElseThrow(() ->
                                    new IllegalStateException("Permission missing during bootstrap: " + type));
                    return RolePermission.builder()
                            .role(role)
                            .permission(permission)
                            .assignedAt(now)
                            .build();
                })
                .collect(Collectors.toList());

        rolePermissionRepository.saveAll(mappings);

        log.info("Assigned {} permissions to role {}", mappings.size(), role.getType());
    }

    private Role requireRole(RoleType type) {
        return roleRepository.findByType(type)
                .orElseThrow(() ->
                        new IllegalStateException("Role missing during bootstrap: " + type));
    }

    private String getRoleDescription(RoleType type) {
        return switch (type) {
            case ROLE_USER -> "Default authenticated user";
            case ROLE_ADMIN -> "IAM administrator with elevated privileges";
            case ROLE_OWNER -> "IAM system owner with full access";
        };
    }

    private String getPermissionDescription(PermissionType type) {
        return switch (type) {
            case USER_CREATE -> "Create users";
            case USER_READ -> "Read user information";
            case USER_UPDATE -> "Update user information";
            case USER_DISABLE -> "Disable user accounts";
            case USER_ROLE_ASSIGN -> "Assign roles to users";
            case ROLE_READ -> "Read roles";
            case ROLE_MANAGE -> "Manage roles";
            case PERMISSION_READ -> "Read permissions";
            case PERMISSION_MANAGE -> "Manage permissions";
            case TOKEN_REVOKE -> "Revoke tokens";
            case SESSION_TERMINATE -> "Terminate sessions";
            case RATE_LIMIT_RESET -> "Reset rate limits";
            case AUDIT_READ -> "Read audit logs";
        };
    }
}
