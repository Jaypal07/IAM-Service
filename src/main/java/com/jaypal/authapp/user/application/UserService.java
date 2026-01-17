package com.jaypal.authapp.user.application;

import com.jaypal.authapp.user.dto.*;

import java.util.UUID;

public interface UserService {

    UserResponseDto createUser(UserCreateRequest request);

    UserResponseDto getSelf(UUID userId);

    UserResponseDto updateSelf(UUID userId, UserUpdateRequest request);

    void deleteSelf(UUID userId);
}
