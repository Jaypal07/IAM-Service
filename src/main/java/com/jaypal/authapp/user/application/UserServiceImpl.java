package com.jaypal.authapp.user.application;

import com.jaypal.authapp.user.dto.*;
import com.jaypal.authapp.user.exception.ResourceNotFoundException;
import com.jaypal.authapp.user.exception.EmailAlreadyExistsException;
import com.jaypal.authapp.user.mapper.UserMapper;
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

import java.util.List;
import java.util.UUID;

@Service
@RequiredArgsConstructor
@Slf4j
public class UserServiceImpl implements UserService {

    private final UserRepository userRepository;
    private final PasswordEncoder passwordEncoder;
    private final UserRoleService userRoleService;

    @Override
    @Transactional
    public UserResponseDto createUser(UserCreateRequest req) {
        log.info("User creation started. email={}", req.email());

        try {
            User user = User.createLocal(
                    req.email(),
                    passwordEncoder.encode(req.password()),
                    req.name()
            );

            User saved = userRepository.save(user);

            // DEFAULT ROLE
            userRoleService.assignRole(saved, RoleType.ROLE_USER);

            log.info("User created successfully. userId={}", saved.getId());
            return UserMapper.toResponse(saved);

        } catch (DataIntegrityViolationException ex) {
            log.warn("User creation failed. Email already exists. email={}", req.email());
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
        log.debug("Fetching user by ID. userId={}", userId);
        return UserMapper.toResponse(find(userId));
    }

    @Override
    @Transactional(readOnly = true)
    public UserResponseDto getUserByEmail(String email) {
        log.debug("Fetching user by email. email={}", email);

        User user = userRepository.findByEmail(email)
                .orElseThrow(() -> {
                    log.warn("User not found by email. email={}", email);
                    return new ResourceNotFoundException("User not found with given email id");
                });

        return UserMapper.toResponse(user);
    }

    @Override
    @PreAuthorize("hasAuthority('USER_READ')")
    @Transactional(readOnly = true)
    public List<UserResponseDto> getAllUsers() {
        log.debug("Fetching all users");
        return userRepository.findAll()
                .stream()
                .map(UserMapper::toResponse)
                .toList();
    }

    @Override
    @Transactional
    public UserResponseDto updateUser(String userId, UserUpdateRequest req) {
        log.info("Updating user. userId={}", userId);

        User user = find(userId);
        user.updateProfile(req.name(), req.image());

        if (req.password() != null && !req.password().isBlank()) {
            log.info("Updating user password. userId={}", userId);
            user.changePassword(passwordEncoder.encode(req.password()));
        }

        return UserMapper.toResponse(userRepository.save(user));
    }

    /* =========================
        ADMIN UPDATE
      ========================= */

    @Override
    @PreAuthorize("hasAuthority('USER_UPDATE')")
    @Transactional
    public UserResponseDto adminUpdateUser(String userId, AdminUserUpdateRequest req) {
        log.warn("Admin update invoked. userId={}", userId);

        User user = find(userId);

        if (req.name() != null || req.image() != null) {
            user.updateProfile(req.name(), req.image());
        }

        if (req.enabled() != null) {
            if (req.enabled()) {
                user.enable();
            } else {
                user.disable();
            }
        }

        return UserMapper.toResponse(userRepository.save(user));
    }


    @Override
    @Transactional
    public User createAndReturnDomainUser(UserCreateRequest req) {
        log.info("Creating domain user. email={}", req.email());

        try {
            User user = User.createLocal(
                    req.email(),
                    passwordEncoder.encode(req.password()),
                    req.name()
            );

            User saved = userRepository.save(user);
            log.info("Domain user created. userId={}", saved.getId());

            return saved;

        } catch (DataIntegrityViolationException ex) {
            log.warn("Domain user creation failed. Email exists. email={}", req.email());
            throw new EmailAlreadyExistsException();
        }
    }

    /**
     * ADMIN ROLE MANAGEMENT (SEPARATE, EXPLICIT)
     */
    @Override
    @PreAuthorize("hasAuthority('USER_ROLE_ASSIGN')")
    @Transactional
    public UserResponseDto adminUpdateUserRoles(
            String userId,
            AdminUserRoleUpdateRequest req
    ) {
        log.warn("Admin role update invoked. userId={}", userId);

        User user = find(userId);

        if (req.addRoles() != null) {
            for (String role : req.addRoles()) {
                userRoleService.assignRole(user, RoleType.valueOf(role));
            }
        }

        if (req.removeRoles() != null) {
            for (String role : req.removeRoles()) {
                userRoleService.removeRole(user, RoleType.valueOf(role));
            }
        }

        return UserMapper.toResponse(user);
    }

    @Override
    @PreAuthorize("hasAuthority('USER_READ')")
    @Transactional
    public void deleteUser(String userId) {
        log.warn("Deleting user. userId={}", userId);
        userRepository.delete(find(userId));
    }

    private User find(String id) {
        return userRepository.findById(UUID.fromString(id))
                .orElseThrow(() -> {
                    log.warn("User not found. userId={}", id);
                    return new ResourceNotFoundException("User not found with ID: " + id);
                });
    }
}
