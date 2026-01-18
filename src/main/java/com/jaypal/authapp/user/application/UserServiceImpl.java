package com.jaypal.authapp.user.application;

import com.jaypal.authapp.config.PasswordPolicy;
import com.jaypal.authapp.user.dto.*;
import com.jaypal.authapp.user.exception.EmailAlreadyExistsException;
import com.jaypal.authapp.user.exception.ResourceNotFoundException;
import com.jaypal.authapp.user.mapper.UserMapper;
import com.jaypal.authapp.user.model.User;
import com.jaypal.authapp.user.repository.UserRepository;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.dao.DataIntegrityViolationException;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.util.Objects;
import java.util.UUID;

@Slf4j
@Service
@RequiredArgsConstructor
public class UserServiceImpl implements UserService {

    private final UserRepository userRepository;
    private final PasswordEncoder passwordEncoder;
    private final UserProvisioningService userProvisioningService;
    private final PermissionService permissionService;
    private final PasswordPolicy passwordPolicy;

    // -------------------------------------------------------------------------
    // CREATE
    // -------------------------------------------------------------------------

    @Override
    @Transactional
    public UserResponseDto createUser(UserCreateRequest req) {
        Objects.requireNonNull(req, "UserCreateRequest cannot be null");

        passwordPolicy.validate(req.password());

        User user = User.createLocal(
                req.email().toLowerCase(),
                passwordEncoder.encode(req.password()),
                req.name()
        );

        try {
            userRepository.saveAndFlush(user);

            // Assign default roles
            userProvisioningService.provisionNewUser(user);

            user.bumpPermissionVersion();
            userRepository.saveAndFlush(user);

            log.info("User created. userId={}", user.getId());

            // 🔑 RELOAD WITH ROLES
            return UserMapper.toResponse(
                    user,
                    permissionService.resolvePermissions(user.getId())
            );

        } catch (DataIntegrityViolationException ex) {
            throw new EmailAlreadyExistsException();
        }
    }

    // -------------------------------------------------------------------------
    // READ
    // -------------------------------------------------------------------------

    @Override
    @Transactional(readOnly = true)
    public UserResponseDto getSelf(UUID userId) {
        return hydrate(requireEnabledUser(userId));
    }

    // -------------------------------------------------------------------------
    // UPDATE
    // -------------------------------------------------------------------------

    @Override
    @Transactional
    public UserResponseDto updateSelf(UUID userId, UserUpdateRequest req) {
        Objects.requireNonNull(req, "UserUpdateRequest cannot be null");

        User user = requireEnabledUser(userId);

        ImageUrlValidator.validate(req.image());
        user.updateProfile(req.name(), req.image());

        if (req.password() != null && !req.password().isBlank()) {
            passwordPolicy.validate(req.password());
            user.changePassword(passwordEncoder.encode(req.password()));
        }

        userRepository.saveAndFlush(user);

        // 🔑 RELOAD WITH ROLES
        return hydrate(requireEnabledUser(userId));
    }

    // -------------------------------------------------------------------------
    // DELETE
    // -------------------------------------------------------------------------

    @Override
    @Transactional
    public void deleteSelf(UUID userId) {
        User user = requireEnabledUser(userId);
        user.disable();
        user.bumpPermissionVersion();
        userRepository.save(user);
    }

    // -------------------------------------------------------------------------
    // INTERNAL
    // -------------------------------------------------------------------------

    private User requireEnabledUser(UUID id) {
        User user = userRepository.findByIdWithRoles(id)
                .orElseThrow(() -> new ResourceNotFoundException("User not found"));

        if (!user.isEnabled()) {
            throw new ResourceNotFoundException("User not found");
        }

        return user;
    }

    private UserResponseDto hydrate(User user) {
        return UserMapper.toResponse(
                user,
                permissionService.resolvePermissions(user.getId())
        );
    }
}
