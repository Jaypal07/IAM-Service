package com.jaypal.authapp.dto.auth;

import com.jaypal.authapp.dto.user.UserResponseDto;

public record AuthLoginResult(
        UserResponseDto user,
        String accessToken,
        String refreshToken,
        long refreshExpiresAtEpochSeconds
) {}
