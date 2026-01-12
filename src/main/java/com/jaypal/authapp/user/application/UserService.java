package com.jaypal.authapp.user.application;

import com.jaypal.authapp.user.dto.*;
import com.jaypal.authapp.user.model.User;

import java.util.UUID;

public interface UserService {

    /* =====================
       PUBLIC SELF-SERVICE
       ===================== */

    UserResponseDto createUser(UserCreateRequest request);

    UserResponseDto getSelf(UUID userId);

    UserResponseDto updateSelf(UUID userId, UserUpdateRequest request);

    void deleteSelf(UUID userId);

    /* =====================
       ADMIN OPERATIONS
       ===================== */

    UserResponseDto getUserById(UUID userId);

    UserResponseDto getUserByEmail(String email);

    UserResponseDto adminUpdateUser(
            UUID userId,
            AdminUserUpdateRequest request
    );

    UserResponseDto adminUpdateUserRoles(
            UUID userId,
            AdminUserRoleUpdateRequest request
    );

    void adminDisableUser(UUID userId);

    /* =====================
       INTERNAL (AUTH ONLY)
       ===================== */

    User createAndReturnDomainUser(UserCreateRequest request);
}
