package com.jaypal.authapp.user.application;

import com.jaypal.authapp.config.PasswordPolicy;
import com.jaypal.authapp.user.dto.*;
import com.jaypal.authapp.user.exception.EmailAlreadyExistsException;
import com.jaypal.authapp.user.exception.ResourceNotFoundException;
import com.jaypal.authapp.user.mapper.UserMapper;
import com.jaypal.authapp.user.model.PermissionType;
import com.jaypal.authapp.user.model.RoleType;
import com.jaypal.authapp.user.model.User;
import com.jaypal.authapp.user.repository.UserRepository;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.dao.DataIntegrityViolationException;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.util.Objects;
import java.util.Set;
import java.util.UUID;

@Slf4j
@Service
@RequiredArgsConstructor
public class UserServiceImpl implements UserService {

    private final UserRepository userRepository;
    private final PasswordEncoder passwordEncoder;
    private final UserProvisioningService userProvisioningService;
    private final UserRoleService userRoleService;
    private final PermissionService permissionService;
    private final PasswordPolicy passwordPolicy;

    /* =====================
       SELF-SERVICE
       ===================== */

    @Override
    @Transactional
    public UserResponseDto createUser(UserCreateRequest req) {
        Objects.requireNonNull(req, "Request cannot be null");
        passwordPolicy.validate(req.password());

        try {
            User user = User.createLocal(
                    req.email(),
                    passwordEncoder.encode(req.password()),
                    req.name()
            );

            User saved = userRepository.save(user);
            userProvisioningService.provisionNewUser(saved);

            return hydrate(saved);

        } catch (DataIntegrityViolationException ex) {
            throw new EmailAlreadyExistsException();
        }
    }

    @Override
    @Transactional(readOnly = true)
    public UserResponseDto getSelf(UUID userId) {
        return hydrate(requireUser(userId));
    }

    @Override
    @Transactional
    public UserResponseDto updateSelf(UUID userId, UserUpdateRequest req) {
        Objects.requireNonNull(req, "Update request cannot be null");

        User user = requireUser(userId);
        user.updateProfile(req.name(), req.image());

        if (req.password() != null && !req.password().isBlank()) {
            passwordPolicy.validate(req.password());
            user.changePassword(passwordEncoder.encode(req.password()));
            user.bumpPermissionVersion();
        }

        userRepository.save(user);
        return hydrate(user);
    }

    @Override
    @Transactional
    public void deleteSelf(UUID userId) {
        User user = requireUser(userId);
        user.disable();
        user.bumpPermissionVersion();
        userRepository.save(user);
        log.info("User self-disabled account: {}", userId);
    }

    /* =====================
       ADMIN
       ===================== */

    @Override
    @PreAuthorize("hasAuthority('USER_READ')")
    @Transactional(readOnly = true)
    public UserResponseDto getUserById(UUID userId) {
        return hydrate(requireUser(userId));
    }

    @Override
    @PreAuthorize("hasAuthority('USER_READ')")
    @Transactional(readOnly = true)
    public UserResponseDto getUserByEmail(String email) {
        User user = userRepository.findByEmailWithRoles(email)
                .orElseThrow(() -> new ResourceNotFoundException("User not found"));
        return hydrate(user);
    }

    @Override
    @PreAuthorize("hasAuthority('USER_UPDATE')")
    @Transactional
    public UserResponseDto adminUpdateUser(UUID userId, AdminUserUpdateRequest req) {
        Objects.requireNonNull(req, "Admin request cannot be null");

        User user = requireUser(userId);

        if (req.name() != null || req.image() != null) {
            user.updateProfile(req.name(), req.image());
        }

        if (req.enabled() != null) {
            if (req.enabled()) user.enable();
            else user.disable();

            user.bumpPermissionVersion();
        }

        userRepository.save(user);
        return hydrate(user);
    }

    @Override
    @PreAuthorize("hasAuthority('USER_ROLE_ASSIGN')")
    @Transactional
    public UserResponseDto adminUpdateUserRoles(UUID userId, AdminUserRoleUpdateRequest req) {
        Objects.requireNonNull(req, "Role request cannot be null");

        User user = requireUser(userId);

        if (req.addRoles() != null) {
            req.addRoles().forEach(r ->
                    userRoleService.assignRole(user, RoleType.valueOf(r)));
        }

        if (req.removeRoles() != null) {
            req.removeRoles().forEach(r ->
                    userRoleService.removeRole(user, RoleType.valueOf(r)));
        }

        user.bumpPermissionVersion();
        userRepository.save(user);

        return hydrate(user);
    }

    @Override
    @PreAuthorize("hasAuthority('USER_DISABLE')")
    @Transactional
    public void adminDisableUser(UUID userId) {
        User user = requireUser(userId);
        user.disable();
        user.bumpPermissionVersion();
        userRepository.save(user);
    }

    /* =====================
       INTERNAL
       ===================== */

    @Override
    @Transactional
    public User createAndReturnDomainUser(UserCreateRequest req) {
        passwordPolicy.validate(req.password());

        User user = User.createLocal(
                req.email(),
                passwordEncoder.encode(req.password()),
                req.name()
        );

        User saved = userRepository.save(user);
        userProvisioningService.provisionNewUser(saved);
        return saved;
    }

    /* =====================
       HELPERS
       ===================== */

    private User requireUser(UUID id) {
        return userRepository.findByIdWithRoles(id)
                .orElseThrow(() -> new ResourceNotFoundException("User not found"));
    }

    private UserResponseDto hydrate(User user) {
        Set<PermissionType> perms = permissionService.resolvePermissions(user.getId());
        return UserMapper.toResponse(user, perms);
    }

}
