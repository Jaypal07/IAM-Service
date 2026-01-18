package com.jaypal.authapp.domain.user.service;

import com.jaypal.authapp.domain.audit.service.AuthAuditService;
import com.jaypal.authapp.domain.audit.entity.*;
import com.jaypal.authapp.domain.token.service.RefreshTokenService;
import com.jaypal.authapp.domain.user.entity.Role;
import com.jaypal.authapp.domain.user.entity.RoleType;
import com.jaypal.authapp.domain.user.entity.User;
import com.jaypal.authapp.domain.user.entity.UserRole;
import com.jaypal.authapp.domain.user.repository.RoleRepository;
import com.jaypal.authapp.domain.user.repository.UserRoleRepository;
import com.jaypal.authapp.user.model.*;
import com.jaypal.authapp.user.repository.*;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.cache.CacheManager;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.transaction.support.TransactionSynchronization;
import org.springframework.transaction.support.TransactionSynchronizationManager;

import java.time.Instant;
import java.util.Objects;
import java.util.UUID;

@Slf4j
@Service
@RequiredArgsConstructor
public class UserRoleService {

    private static final String POST_COMMIT_KEY =
            UserRoleService.class.getName() + ".POST_COMMIT_REGISTERED";

    private final UserRoleRepository userRoleRepository;
    private final RoleRepository roleRepository;
    private final RefreshTokenService refreshTokenService;
    private final AuthAuditService auditService;
    private final CacheManager cacheManager;

    @Transactional
    public void assignRole(User user, RoleType roleType) {
        Objects.requireNonNull(user, "User cannot be null");
        Objects.requireNonNull(roleType, "Role type cannot be null");

        assignRoleInternal(user, roleType);
        registerPostCommitActionsOnce(user.getId());
    }

    @Transactional
    public void removeRole(User user, RoleType roleType) {
        Objects.requireNonNull(user, "User cannot be null");
        Objects.requireNonNull(roleType, "Role type cannot be null");

        Role role = roleRepository.findByType(roleType)
                .orElseThrow(() -> new IllegalStateException("Role not initialized: " + roleType));

        if (user.getUserRoles().size() <= 1) {
            throw new IllegalStateException("User must have at least one role");
        }


        userRoleRepository.deleteByUserAndRole(user, role);
        // ✅ CRITICAL: keep persistence context consistent
        user.getUserRoles().removeIf(ur -> ur.getRole().equals(role));

        user.bumpPermissionVersion();
        auditRoleRemoval(user, roleType);

        registerPostCommitActionsOnce(user.getId());

        log.info("Role removed: user={}, role={}", user.getId(), roleType);
    }

    /**
     * INTERNAL USE ONLY
     * Does NOT register post-commit hooks.
     */
    @Transactional
    void assignRoleInternal(User user, RoleType roleType) {
        Role role = roleRepository.findByType(roleType)
                .orElseThrow(() -> new IllegalStateException("Role not initialized: " + roleType));

        if (userRoleRepository.existsByUserAndRole(user, role)) {
            return;
        }

        if (roleType.isOwner()) {
            throw new IllegalStateException(
                    "ROLE_OWNER assignment is restricted to system bootstrap"
            );
        }

        UserRole userRole = UserRole.builder()
                .user(user)
                .role(role)
                .assignedAt(Instant.now())
                .build();

        userRoleRepository.save(userRole);

        // 🔑 THIS IS THE MISSING LINE
        user.getUserRoles().add(userRole);

        user.bumpPermissionVersion();
        auditRoleAssignment(user, roleType);
    }

    private void registerPostCommitActionsOnce(UUID userId) {
        if (!TransactionSynchronizationManager.isSynchronizationActive()) {
            return;
        }

        if (TransactionSynchronizationManager.hasResource(POST_COMMIT_KEY)) {
            return;
        }

        TransactionSynchronizationManager.bindResource(POST_COMMIT_KEY, Boolean.TRUE);

        TransactionSynchronizationManager.registerSynchronization(
                new TransactionSynchronization() {
                    @Override
                    public void afterCommit() {
                        evictPermissionCache(userId);
                        refreshTokenService.revokeAllForUser(userId);
                    }
                }
        );
    }

    private void evictPermissionCache(UUID userId) {
        var cache = cacheManager.getCache("userPermissions");
        if (cache != null) {
            cache.evict(userId);
            log.debug("Permission cache evicted after commit. userId={}", userId);
        }
    }

    private void auditRoleAssignment(User user, RoleType roleType) {
        auditService.record(
                AuditCategory.AUTHORIZATION,
                AuthAuditEvent.ROLE_ASSIGNED,
                AuditOutcome.SUCCESS,
                AuditSubject.userId(user.getId().toString()),
                null,
                AuthProvider.SYSTEM,
                null
        );
    }

    private void auditRoleRemoval(User user, RoleType roleType) {
        auditService.record(
                AuditCategory.AUTHORIZATION,
                AuthAuditEvent.ROLE_REMOVED,
                AuditOutcome.SUCCESS,
                AuditSubject.userId(user.getId().toString()),
                null,
                AuthProvider.SYSTEM,
                null
        );
    }
}
