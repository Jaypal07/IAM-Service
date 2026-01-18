package com.jaypal.authapp.domain.infrastructure.oauth.model;

public record ValidatedOAuthUserInfo(
        String providerId,
        String email,
        String name,
        String image
) {}
