package com.jaypal.authapp.domain.user.service;

import com.jaypal.authapp.domain.dto.user.AdminUserCreateRequest;
import com.jaypal.authapp.domain.dto.user.AdminUserRoleUpdateRequest;
import com.jaypal.authapp.domain.dto.user.UserResponseDto;
import com.jaypal.authapp.user.dto.*;

import java.util.List;
import java.util.UUID;

public interface AdminUserService {

    UserResponseDto createUser(AdminUserCreateRequest request);

    UserResponseDto getUserById(UUID userId);

    UserResponseDto getUserByEmail(String email);

    List<UserResponseDto> getAllUsers();

    UserResponseDto updateUserRoles(
            UUID userId,
            AdminUserRoleUpdateRequest request
    );

    void disableUser(UUID userId);
}
