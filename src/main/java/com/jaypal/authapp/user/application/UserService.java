package com.jaypal.authapp.user.application;

import com.jaypal.authapp.dto.UserCreateRequest;
import com.jaypal.authapp.dto.AdminUserUpdateRequest;
import com.jaypal.authapp.dto.UserResponseDto;
import com.jaypal.authapp.dto.UserUpdateRequest;
import com.jaypal.authapp.user.model.User;

import java.util.List;

public interface UserService {

    UserResponseDto createUser(UserCreateRequest request);

    UserResponseDto getUserById(String userId);

    UserResponseDto getUserByEmail(String email);

    List<UserResponseDto> getAllUsers();

    UserResponseDto updateUser(String userId, UserUpdateRequest request);

    UserResponseDto adminUpdateUser(
            String userId,
            AdminUserUpdateRequest request
    );

    void deleteUser(String userId);

    /**
     * INTERNAL USE ONLY (Auth flows)
     */
    User createAndReturnDomainUser(UserCreateRequest request);
}
