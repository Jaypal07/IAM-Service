package com.jaypal.authapp.domain.infrastructure.security.jwt;

public enum TokenType {
    ACCESS;

    public static TokenType from(String value) {
        return TokenType.valueOf(value.toUpperCase());
    }
}
