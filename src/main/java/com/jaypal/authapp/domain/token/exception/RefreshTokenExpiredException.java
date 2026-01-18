package com.jaypal.authapp.domain.token.exception;

public class RefreshTokenExpiredException extends RefreshTokenException {
    public RefreshTokenExpiredException() {
        super("Refresh token expired");
    }
}
