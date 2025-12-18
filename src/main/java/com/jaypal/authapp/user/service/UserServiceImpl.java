package com.jaypal.authapp.user.service;

import com.jaypal.authapp.exception.ResourceNotFoundExceptions;
import com.jaypal.authapp.dto.*;
import com.jaypal.authapp.user.mapper.UserMapper;
import com.jaypal.authapp.user.model.Role;
import com.jaypal.authapp.user.model.User;
import com.jaypal.authapp.user.repository.UserRepository;
import lombok.RequiredArgsConstructor;
import org.modelmapper.ModelMapper;
import org.springframework.dao.DataIntegrityViolationException;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.util.List;
import java.util.UUID;
import java.util.stream.Collectors;

@Service
@RequiredArgsConstructor
public class UserServiceImpl implements UserService {

    private final UserRepository userRepository;
    private final PasswordEncoder passwordEncoder;
    private final ModelMapper mapper;

    @Override
    @Transactional
    public UserResponseDto createUser(UserCreateRequest req) {

        try {
            User user = User.createLocal(
                    req.email(),
                    passwordEncoder.encode(req.password()),
                    req.name()
            );
            return UserMapper.toResponse(userRepository.save(user));

        } catch (DataIntegrityViolationException ex) {
            throw new IllegalArgumentException("Email already exists");
        }
    }

    @Override
    @Transactional(readOnly = true)
    public UserResponseDto getUserById(String userId) {
        return UserMapper.toResponse(find(userId));
    }

    @Override
    @Transactional(readOnly = true)
    public UserResponseDto getUserByEmail(String email) {
        return toResponse(
                userRepository.findByEmail(email)
                        .orElseThrow(() ->
                                new ResourceNotFoundExceptions(
                                        "User not found with given email id"
                                ))
        );
    }

    @Override
    @Transactional(readOnly = true)
    public List<UserResponseDto> getAllUsers() {
        return userRepository.findAll()
                .stream()
                .map(this::toResponse)
                .toList();
    }

    @Override
    @Transactional
    public UserResponseDto updateUser(
            String userId,
            UserUpdateRequest req
    ) {

        User user = find(userId);

        user.updateProfile(req.name(), req.image());

        if (req.password() != null && !req.password().isBlank()) {
            user.changePassword(
                    passwordEncoder.encode(req.password())
            );
        }

        return toResponse(userRepository.save(user));
    }

    @Override
    @Transactional
    public UserResponseDto adminUpdateUser(
            String userId,
            AdminUserUpdateRequest req
    ) {
        User user = find(userId);

        if (req.name() != null || req.image() != null) {
            user.updateProfile(req.name(), req.image());
        }

        if (req.roles() != null) {
            user.setRoles(
                    req.roles().stream()
                            .map(r -> mapper.map(r, Role.class))
                            .collect(Collectors.toSet())
            );
        }

        if (req.enabled()) {
            user.enable();
        } else {
            user.disable();
        }

        return toResponse(userRepository.save(user));
    }

    @Override
    @Transactional
    public User createAndReturnDomainUser(UserCreateRequest req) {

        try {
            User user = User.createLocal(
                    req.email(),
                    passwordEncoder.encode(req.password()),
                    req.name()
            );

            return userRepository.save(user);

        } catch (DataIntegrityViolationException ex) {
            throw new IllegalArgumentException("Email already exists");
        }
    }



    @Override
    @Transactional
    public void deleteUser(String userId) {
        userRepository.delete(find(userId));
    }

    // ---------------- INTERNAL ----------------

    private User find(String id) {
        return userRepository.findById(UUID.fromString(id))
                .orElseThrow(() ->
                        new ResourceNotFoundExceptions(
                                "User not found with ID: " + id
                        ));
    }


    private UserResponseDto toResponse(User user) {
        return UserMapper.toResponse(user);
    }
}
