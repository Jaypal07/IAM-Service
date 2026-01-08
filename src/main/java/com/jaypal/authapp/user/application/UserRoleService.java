package com.jaypal.authapp.user.application;

import com.jaypal.authapp.token.application.RefreshTokenService;
import com.jaypal.authapp.user.model.*;
import com.jaypal.authapp.user.repository.*;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.time.Instant;

@Service
@RequiredArgsConstructor
public class UserRoleService {

    private final UserRoleRepository userRoleRepository;
    private final RoleRepository roleRepository;
    private final RefreshTokenService refreshTokenService;

    @Transactional
    public void assignRole(User user, RoleType roleType) {
        Role role = roleRepository.findByType(roleType)
                .orElseThrow(() -> new IllegalStateException("Role not initialized"));

        if (userRoleRepository.existsByUserAndRole(user, role)) return;

        userRoleRepository.save(
                UserRole.builder()
                        .user(user)
                        .role(role)
                        .assignedAt(Instant.now())
                        .build()
        );
        user.bumpPermissionVersion();
        refreshTokenService.revokeAllForUser(user.getId());
    }

    @Transactional
    public void removeRole(User user, RoleType roleType) {
        Role role = roleRepository.findByType(roleType)
                .orElseThrow(() -> new IllegalStateException("Role not initialized"));

        userRoleRepository.deleteByUserAndRole(user, role);
        user.bumpPermissionVersion();
        refreshTokenService.revokeAllForUser(user.getId());
    }
}
