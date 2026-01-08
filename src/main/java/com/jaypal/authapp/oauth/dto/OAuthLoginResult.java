package com.jaypal.authapp.oauth.dto;

public record OAuthLoginResult(
        String accessToken,
        String refreshToken,
        long refreshTtlSeconds
) {}
