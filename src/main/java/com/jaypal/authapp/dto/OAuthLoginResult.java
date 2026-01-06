package com.jaypal.authapp.dto;

public record OAuthLoginResult(
        String accessToken,
        String refreshToken,
        long refreshTtlSeconds
) {}
