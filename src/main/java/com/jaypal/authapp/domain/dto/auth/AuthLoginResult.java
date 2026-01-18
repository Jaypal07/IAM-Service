package com.jaypal.authapp.domain.dto.auth;

import com.jaypal.authapp.domain.dto.user.UserResponseDto;

public record AuthLoginResult(
        UserResponseDto user,
        String accessToken,
        String refreshToken,
        long refreshExpiresAtEpochSeconds
) {}
