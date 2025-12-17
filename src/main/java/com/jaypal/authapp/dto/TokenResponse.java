package com.jaypal.authapp.dto;


public record TokenResponse(
        String accessToken,
        long expiresIn,
        String tokenType,
        UserDto user
) {
    public static TokenResponse of(String accessToken, long expiresIn, UserDto user) {
        return new TokenResponse(accessToken, expiresIn, "Bearer", user);
    }
}
