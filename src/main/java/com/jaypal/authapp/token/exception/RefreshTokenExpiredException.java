package com.jaypal.authapp.token.exception;

public class RefreshTokenExpiredException extends RefreshTokenException {
    public RefreshTokenExpiredException() {
        super("Refresh token expired");
    }
}
