package com.jaypal.authapp.dto.auth;

import com.jaypal.authapp.dto.user.UserResponseDto;

public record TokenResponse(
        String accessToken,
        long expiresIn,
        String tokenType,
        UserResponseDto user
) {
    public static TokenResponse of(String accessToken, long expiresIn, UserResponseDto user) {
        return new TokenResponse(accessToken, expiresIn, "Bearer", user);
    }
}
