package com.jaypal.authapp.domain.user.service;

import com.jaypal.authapp.service.auth.EmailVerificationService;
import com.jaypal.authapp.config.properties.PasswordPolicy;
import com.jaypal.authapp.dto.user.AdminUserCreateRequest;
import com.jaypal.authapp.dto.user.AdminUserRoleUpdateRequest;
import com.jaypal.authapp.dto.user.UserResponseDto;
import com.jaypal.authapp.domain.user.exception.EmailAlreadyExistsException;
import com.jaypal.authapp.domain.user.exception.InvalidRoleOperationException;
import com.jaypal.authapp.domain.user.exception.ResourceNotFoundException;
import com.jaypal.authapp.mapper.UserMapper;
import com.jaypal.authapp.domain.user.entity.RoleType;
import com.jaypal.authapp.domain.user.entity.User;
import com.jaypal.authapp.domain.user.repository.UserRepository;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.dao.DataIntegrityViolationException;
import org.springframework.security.access.AccessDeniedException;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.util.*;
import java.util.stream.Collectors;

@Slf4j
@Service
@RequiredArgsConstructor
public class AdminUserServiceImpl implements AdminUserService {

    private final UserRepository userRepository;
    private final UserRoleService userRoleService;
    private final UserProvisioningService userProvisioningService;
    private final PermissionService permissionService;
    private final PasswordEncoder passwordEncoder;
    private final PasswordPolicy passwordPolicy;
    private final EmailVerificationService emailVerificationService;

    // -------------------------------------------------------------------------
    // CREATE
    // -------------------------------------------------------------------------

    @Override
    @PreAuthorize("hasAuthority('USER_CREATE')")
    @Transactional
    public UserResponseDto createUser(AdminUserCreateRequest req) {
        Objects.requireNonNull(req, "AdminUserCreateRequest cannot be null");

        log.debug("Admin creating user. email={}, roles={}", req.email(), req.roles());
        passwordPolicy.validate(req.password());

        try {
            User user = User.createLocal(
                    req.email(),
                    passwordEncoder.encode(req.password()),
                    req.name()
            );

            userRepository.saveAndFlush(user);

            if (req.roles() != null && !req.roles().isEmpty()) {
                for (String role : req.roles()) {
                    RoleType roleType = RoleType.valueOf(role);

                    if (roleType.isOwner()) {
                        throw new AccessDeniedException(
                                "Admin is not allowed to assign ROLE_OWNER"
                        );
                    }

                    userRoleService.assignRoleInternal(user, roleType);
                }
            } else {
                userProvisioningService.provisionNewUser(user);
            }

            user.bumpPermissionVersion();
            userRepository.saveAndFlush(user);

            emailVerificationService.createVerificationToken(user.getId());

            log.info("Admin created user. userId={}", user.getId());

            // 🔑 RELOAD WITH ROLES
            return hydrate(requireUser(user.getId()));

        } catch (DataIntegrityViolationException ex) {
            log.warn("Duplicate email during admin create. email={}", req.email());
            throw new EmailAlreadyExistsException();
        }
    }

    // -------------------------------------------------------------------------
    // READ
    // -------------------------------------------------------------------------

    @Override
    @PreAuthorize("hasAuthority('USER_UPDATE')")
    @Transactional(readOnly = true)
    public UserResponseDto getUserById(UUID userId) {
        log.debug("Admin fetching user by id. userId={}", userId);
        return hydrate(requireUser(userId));
    }

    @Override
    @PreAuthorize("hasAuthority('USER_UPDATE')")
    @Transactional(readOnly = true)
    public UserResponseDto getUserByEmail(String email) {
        log.debug("Admin fetching user by email. email={}", email);

        User user = userRepository.findByEmailWithRoles(email)
                .orElseThrow(() -> new ResourceNotFoundException("User not found with email"));

        return hydrate(user);
    }

    @Override
    @PreAuthorize("hasAuthority('USER_UPDATE')")
    @Transactional(readOnly = true)
    public List<UserResponseDto> getAllUsers() {
        List<User> users = userRepository.findAllWithRoles();
        log.debug("Admin fetched all users. count={}", users.size());
        return users.stream().map(this::hydrate).toList();
    }

    // -------------------------------------------------------------------------
    // UPDATE ROLES
    // -------------------------------------------------------------------------

    @Override
    @PreAuthorize("hasAuthority('USER_ROLE_ASSIGN')")
    @Transactional
    public UserResponseDto updateUserRoles(UUID userId, AdminUserRoleUpdateRequest request) {
        Objects.requireNonNull(request, "AdminUserRoleUpdateRequest cannot be null");

        log.debug(
                "Admin updating roles. userId={}, add={}, remove={}",
                userId,
                request.addRoles(),
                request.removeRoles()
        );

        User user = requireUser(userId);

        // ---------------------------------------------------------------------
        // 1. Resolve current roles
        // ---------------------------------------------------------------------
        Set<RoleType> currentRoles = user.getUserRoles()
                .stream()
                .map(ur -> ur.getRole().getType())
                .collect(Collectors.toSet());

        // ---------------------------------------------------------------------
        // 2. Resolve requested changes
        // ---------------------------------------------------------------------
        Set<RoleType> rolesToAdd = request.addRoles() == null
                ? Set.of()
                : request.addRoles().stream()
                .map(RoleType::valueOf)
                .collect(Collectors.toSet());

        Set<RoleType> rolesToRemove = request.removeRoles() == null
                ? Set.of()
                : request.removeRoles().stream()
                .map(RoleType::valueOf)
                .collect(Collectors.toSet());

        // ---------------------------------------------------------------------
        // 3. Enforce ROLE_OWNER restrictions
        // ---------------------------------------------------------------------
        if (rolesToAdd.stream().anyMatch(RoleType::isOwner)) {
            throw new AccessDeniedException(
                    "Admin is not allowed to assign ROLE_OWNER"
            );
        }

        if (rolesToRemove.stream().anyMatch(RoleType::isOwner)) {
            throw new AccessDeniedException(
                    "ROLE_OWNER cannot be removed"
            );
        }

        // ---------------------------------------------------------------------
        // 4. Calculate resulting roles (net effect)
        // ---------------------------------------------------------------------
        Set<RoleType> resultingRoles = new HashSet<>(currentRoles);
        resultingRoles.addAll(rolesToAdd);
        resultingRoles.removeAll(rolesToRemove);

        // ---------------------------------------------------------------------
        // 5. Enforce domain invariant
        // ---------------------------------------------------------------------
        if (resultingRoles.isEmpty()) {
            throw new InvalidRoleOperationException(
                    "User must have at least one role"
            );
        }

        // ---------------------------------------------------------------------
        // 6. Apply role additions
        // ---------------------------------------------------------------------
        for (RoleType role : rolesToAdd) {
            if (!currentRoles.contains(role)) {
                userRoleService.assignRole(user, role);
            }
        }

        // ---------------------------------------------------------------------
        // 7. Apply role removals
        // ---------------------------------------------------------------------
        for (RoleType role : rolesToRemove) {
            if (currentRoles.contains(role)) {
                userRoleService.removeRole(user, role);
            }
        }

        // ---------------------------------------------------------------------
        // 8. Persist and reload
        // ---------------------------------------------------------------------
        user.bumpPermissionVersion();
        userRepository.saveAndFlush(user);

        log.info("Admin updated roles. userId={}", userId);

        // 🔑 Reload with roles & permissions
        return hydrate(requireUser(userId));
    }


    // -------------------------------------------------------------------------
    // DISABLE
    // -------------------------------------------------------------------------

    @Override
    @PreAuthorize("hasAuthority('USER_DISABLE')")
    @Transactional
    public void disableUser(UUID userId) {
        log.warn("Admin disabling user. userId={}", userId);

        User user = requireUser(userId);
        user.disable();
        user.bumpPermissionVersion();
        userRepository.save(user);
    }

    // -------------------------------------------------------------------------
    // INTERNAL
    // -------------------------------------------------------------------------

    private User requireUser(UUID id) {
        return userRepository.findByIdWithRoles(id)
                .orElseThrow(() -> new ResourceNotFoundException("User not found"));
    }

    private UserResponseDto hydrate(User user) {
        return UserMapper.toResponse(
                user,
                permissionService.resolvePermissions(user.getId())
        );
    }
}
