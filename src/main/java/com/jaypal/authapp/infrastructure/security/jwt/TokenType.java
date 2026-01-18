package com.jaypal.authapp.infrastructure.security.jwt;

public enum TokenType {
    ACCESS;

    public static TokenType from(String value) {
        return TokenType.valueOf(value.toUpperCase());
    }
}
