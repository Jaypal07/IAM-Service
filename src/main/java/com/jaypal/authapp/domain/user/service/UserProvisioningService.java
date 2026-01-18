package com.jaypal.authapp.domain.user.service;

import com.jaypal.authapp.domain.user.entity.RoleType;
import com.jaypal.authapp.domain.user.entity.User;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.util.Objects;

@Slf4j
@Service
@RequiredArgsConstructor
public class UserProvisioningService {

    private final UserRoleService userRoleService;

    /**
     * Apply default IAM rules to a newly created user.
     * Idempotent and safe for retries.
     */
    @Transactional
    public void provisionNewUser(User user) {
        Objects.requireNonNull(user, "User cannot be null");

        if (user.getRoles().isEmpty()) {
            log.debug("Assigning default ROLE_USER. userId={}", user.getId());
            userRoleService.assignRoleInternal(user, RoleType.ROLE_USER);
        }
    }

    /**
     * Explicit admin-driven role change.
     * Single entry point for auditing and diagnostics.
     *
     * Does NOT enforce authorization.
     * Caller must enforce admin permissions.
     */
    @Transactional
    public void changeRoleByAdmin(
            User user,
            RoleType role,
            boolean assign
    ) {
        Objects.requireNonNull(user, "User cannot be null");
        Objects.requireNonNull(role, "RoleType cannot be null");

        if (assign) {
            if (role.isOwner()) {
                log.warn(
                        "ROLE_OWNER assignment requested by admin. userId={}",
                        user.getId()
                );
            }

            userRoleService.assignRole(user, role);
            log.info(
                    "Admin assigned role. userId={} role={}",
                    user.getId(),
                    role
            );
        } else {
            userRoleService.removeRole(user, role);
            log.info(
                    "Admin removed role. userId={} role={}",
                    user.getId(),
                    role
            );
        }
    }
}
