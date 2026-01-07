package com.jaypal.authapp.security.bootstrap;

import com.jaypal.authapp.user.model.*;
import com.jaypal.authapp.user.repository.*;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.boot.ApplicationArguments;
import org.springframework.boot.ApplicationRunner;
import org.springframework.stereotype.Component;
import org.springframework.transaction.annotation.Transactional;

import java.time.Instant;
import java.util.EnumSet;
import java.util.Set;

@Slf4j
@Component
@RequiredArgsConstructor
public class PermissionBootstrapRunner implements ApplicationRunner {

    private final RoleRepository roleRepository;
    private final PermissionRepository permissionRepository;
    private final RolePermissionRepository rolePermissionRepository;

    @Override
    @Transactional
    public void run(ApplicationArguments args) {
        log.info("Starting IAM permission bootstrap");

        bootstrapRoles();
        bootstrapPermissions();
        bootstrapRolePermissions();

        log.info("IAM permission bootstrap completed");
    }

    /* =========================
       ROLES
       ========================= */

    private void bootstrapRoles() {
        for (RoleType type : RoleType.values()) {
            roleRepository.findByType(type).orElseGet(() -> {
                log.info("Creating role {}", type);
                return roleRepository.save(
                        Role.builder()
                                .type(type)
                                .description(defaultRoleDescription(type))
                                .immutable(true)
                                .createdAt(Instant.now())
                                .build()
                );
            });
        }
    }

    /* =========================
       PERMISSIONS
       ========================= */

    private void bootstrapPermissions() {
        for (PermissionType type : PermissionType.values()) {
            permissionRepository.findByType(type).orElseGet(() -> {
                log.info("Creating permission {}", type);
                return permissionRepository.save(
                        Permission.builder()
                                .type(type)
                                .description(defaultPermissionDescription(type))
                                .createdAt(Instant.now())
                                .build()
                );
            });
        }
    }

    /* =========================
       ROLE → PERMISSION MAP
       ========================= */

    private void bootstrapRolePermissions() {
        Role user = requireRole(RoleType.ROLE_USER);
        Role admin = requireRole(RoleType.ROLE_ADMIN);
        Role owner = requireRole(RoleType.ROLE_OWNER);

        assignPermissions(user, EnumSet.of(
                PermissionType.USER_READ,
                PermissionType.USER_UPDATE
        ));

        assignPermissions(admin, EnumSet.of(
                PermissionType.USER_READ,
                PermissionType.USER_UPDATE,
                PermissionType.USER_DISABLE,
                PermissionType.USER_ROLE_ASSIGN,
                PermissionType.AUDIT_READ
        ));

        assignPermissions(owner, EnumSet.allOf(PermissionType.class));
    }

    private void assignPermissions(Role role, Set<PermissionType> permissionTypes) {
        for (PermissionType type : permissionTypes) {
            Permission permission = permissionRepository.findByType(type)
                    .orElseThrow(() -> new IllegalStateException("Permission missing: " + type));

            boolean exists = rolePermissionRepository.existsByRoleAndPermission(role, permission);
            if (exists) continue;

            log.info("Assigning permission {} to role {}", type, role.getType());

            rolePermissionRepository.save(
                    RolePermission.builder()
                            .role(role)
                            .permission(permission)
                            .assignedAt(Instant.now())
                            .build()
            );
        }
    }

    /* =========================
       HELPERS
       ========================= */

    private Role requireRole(RoleType type) {
        return roleRepository.findByType(type)
                .orElseThrow(() -> new IllegalStateException("Role missing: " + type));
    }

    private String defaultRoleDescription(RoleType type) {
        return switch (type) {
            case ROLE_USER -> "Default authenticated user";
            case ROLE_ADMIN -> "IAM administrator";
            case ROLE_OWNER -> "IAM system owner";
        };
    }

    private String defaultPermissionDescription(PermissionType type) {
        return type.name().replace('_', ' ').toLowerCase();
    }
}
