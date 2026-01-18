package com.jaypal.authapp.infrastructure.oauth.model;

public record ValidatedOAuthUserInfo(
        String providerId,
        String email,
        String name,
        String image
) {}
