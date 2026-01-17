package com.jaypal.authapp.auth.dto;

public record AuthLoginResult(
        com.jaypal.authapp.user.dto.UserResponseDto user,
        String accessToken,
        String refreshToken,
        long refreshExpiresAtEpochSeconds
) {}
