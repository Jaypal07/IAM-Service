package com.jaypal.authapp.auth.dto;

import java.util.Set;
import java.util.UUID;

public record TokenIntrospectionResponse(
        boolean active,
        UUID userId,
        String email,
        Set<String> roles,
        Set<String> permissions,
        long expiresAt
) {
    public static TokenIntrospectionResponse inactive() {
        return new TokenIntrospectionResponse(
                false,
                null,
                null,
                Set.of(),
                Set.of(),
                0L
        );
    }
}
