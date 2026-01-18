package com.jaypal.authapp.domain.user.service;

import com.jaypal.authapp.domain.dto.user.UserCreateRequest;
import com.jaypal.authapp.domain.dto.user.UserResponseDto;
import com.jaypal.authapp.domain.dto.user.UserUpdateRequest;
import com.jaypal.authapp.user.dto.*;

import java.util.UUID;

public interface UserService {

    UserResponseDto createUser(UserCreateRequest request);

    UserResponseDto getSelf(UUID userId);

    UserResponseDto updateSelf(UUID userId, UserUpdateRequest request);

    void deleteSelf(UUID userId);
}
