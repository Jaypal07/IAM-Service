package com.jaypal.authapp.user.application;

import com.jaypal.authapp.user.dto.*;
import com.jaypal.authapp.user.exception.EmailAlreadyExistsException;
import com.jaypal.authapp.user.exception.ResourceNotFoundException;
import com.jaypal.authapp.user.mapper.UserMapper;
import com.jaypal.authapp.user.model.PermissionType;
import com.jaypal.authapp.user.model.User;
import com.jaypal.authapp.user.repository.UserRepository;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.dao.DataIntegrityViolationException;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.util.Set;
import java.util.UUID;

@Service
@RequiredArgsConstructor
@Slf4j
public class UserServiceImpl implements UserService {

    private final UserRepository userRepository;
    private final PasswordEncoder passwordEncoder;
    private final UserProvisioningService userProvisioningService;
    private final UserRoleService userRoleService;
    private final PermissionService permissionService;

    /* =========================
       LOCAL REGISTRATION
       ========================= */

    @Override
    @Transactional
    public UserResponseDto createUser(UserCreateRequest req) {
        try {
            User user = User.createLocal(
                    req.email(),
                    passwordEncoder.encode(req.password()),
                    req.name()
            );

            User saved = userRepository.save(user);
            userProvisioningService.provisionNewUser(saved);

            // Reload with roles to keep response safe
            User hydrated = requireUserWithRoles(saved.getId());

            return UserMapper.toResponse(
                    hydrated,
                    permissionService.resolvePermissions(hydrated.getId())
            );

        } catch (DataIntegrityViolationException ex) {
            throw new EmailAlreadyExistsException();
        }
    }

    /* =========================
       OAUTH PROVISIONING
       ========================= */

    @Transactional
    public User provisionOAuthUser(User oauthUser) {
        User saved = userRepository.save(oauthUser);
        userProvisioningService.provisionNewUser(saved);
        return saved;
    }

    /* =========================
       INTERNAL DOMAIN CREATION
       ========================= */

    @Override
    @Transactional
    public User createAndReturnDomainUser(UserCreateRequest req) {
        try {
            User user = User.createLocal(
                    req.email(),
                    passwordEncoder.encode(req.password()),
                    req.name()
            );

            User saved = userRepository.save(user);
            userProvisioningService.provisionNewUser(saved);

            return saved;

        } catch (DataIntegrityViolationException ex) {
            throw new EmailAlreadyExistsException();
        }
    }

    /* =========================
       READ OPERATIONS
       ========================= */

    @Override
    @PreAuthorize("hasAuthority('USER_READ')")
    @Transactional(readOnly = true)
    public UserResponseDto getUserById(String userId) {
        User user = requireUserWithRoles(UUID.fromString(userId));
        Set<PermissionType> permissions = permissionService.resolvePermissions(user.getId());
        return UserMapper.toResponse(user, permissions);
    }

    @Override
    @PreAuthorize("hasAuthority('USER_READ')")
    @Transactional(readOnly = true)
    public UserResponseDto getUserByEmail(String email) {
        User user = userRepository.findByEmailWithRoles(email)
                .orElseThrow(ResourceNotFoundException::new);

        Set<PermissionType> permissions = permissionService.resolvePermissions(user.getId());
        return UserMapper.toResponse(user, permissions);
    }

    /* =========================
       SELF UPDATE
       ========================= */

    @Override
    @Transactional
    public UserResponseDto updateUser(String userId, UserUpdateRequest req) {

        User user = requireUserWithRoles(UUID.fromString(userId));

        user.updateProfile(req.name(), req.image());

        if (req.password() != null && !req.password().isBlank()) {
            user.changePassword(passwordEncoder.encode(req.password()));
        }

        Set<PermissionType> permissions = permissionService.resolvePermissions(user.getId());
        return UserMapper.toResponse(user, permissions);
    }

    /* =========================
       ADMIN UPDATE
       ========================= */

    @Override
    @PreAuthorize("hasAuthority('USER_UPDATE')")
    @Transactional
    public UserResponseDto adminUpdateUser(String userId, AdminUserUpdateRequest req) {

        User user = requireUserWithRoles(UUID.fromString(userId));

        if (req.name() != null || req.image() != null) {
            user.updateProfile(req.name(), req.image());
        }

        if (req.enabled() != null) {
            if (req.enabled()) user.enable();
            else user.disable();
        }

        Set<PermissionType> permissions = permissionService.resolvePermissions(user.getId());
        return UserMapper.toResponse(user, permissions);
    }

    @Override
    @PreAuthorize("hasAuthority('USER_ROLE_ASSIGN')")
    @Transactional
    public UserResponseDto adminUpdateUserRoles(
            String userId,
            AdminUserRoleUpdateRequest req
    ) {
        User user = requireUserWithRoles(UUID.fromString(userId));

        if (req.addRoles() != null) {
            req.addRoles().forEach(r ->
                    userRoleService.assignRole(
                            user,
                            Enum.valueOf(com.jaypal.authapp.user.model.RoleType.class, r)
                    )
            );
        }

        if (req.removeRoles() != null) {
            req.removeRoles().forEach(r ->
                    userRoleService.removeRole(
                            user,
                            Enum.valueOf(com.jaypal.authapp.user.model.RoleType.class, r)
                    )
            );
        }

        Set<PermissionType> permissions = permissionService.resolvePermissions(user.getId());
        return UserMapper.toResponse(user, permissions);
    }

    @Override
    @PreAuthorize("hasAuthority('USER_DISABLE')")
    @Transactional
    public void deleteUser(String userId) {
        User user = requireUserWithRoles(UUID.fromString(userId));
        userRepository.delete(user);
    }

    /* =========================
       INTERNAL
       ========================= */

    private User requireUserWithRoles(UUID id) {
        return userRepository.findByIdWithRoles(id)
                .orElseThrow(() ->
                        new ResourceNotFoundException("User not found with ID: " + id)
                );
    }
}
