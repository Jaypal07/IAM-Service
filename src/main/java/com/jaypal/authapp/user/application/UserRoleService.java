package com.jaypal.authapp.user.application;

import com.jaypal.authapp.audit.application.AuthAuditService;
import com.jaypal.authapp.audit.domain.*;
import com.jaypal.authapp.token.application.RefreshTokenService;
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
        registerPostCommitActions(user);
    }

    @Transactional
    public void removeRole(User user, RoleType roleType) {
        Objects.requireNonNull(user, "User cannot be null");
        Objects.requireNonNull(roleType, "Role type cannot be null");

        Role role = roleRepository.findByType(roleType)
                .orElseThrow(() -> new IllegalStateException("Role not initialized: " + roleType));

        userRoleRepository.deleteByUserAndRole(user, role);

        user.bumpPermissionVersion();
        auditRoleRemoval(user, roleType);

        registerPostCommitActions(user);

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
            log.debug("Role already assigned. user={}, role={}", user.getId(), roleType);
            return;
        }

        userRoleRepository.save(
                UserRole.builder()
                        .user(user)
                        .role(role)
                        .assignedAt(Instant.now())
                        .build()
        );

        user.bumpPermissionVersion();
        auditRoleAssignment(user, roleType);

        log.info("Role assigned: user={}, role={}", user.getId(), roleType);
    }

    private void registerPostCommitActions(User user) {
        TransactionSynchronizationManager.registerSynchronization(
                new TransactionSynchronization() {
                    @Override
                    public void afterCommit() {
                        evictPermissionCache(user.getId());
                        refreshTokenService.revokeAllForUser(user.getId());
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
