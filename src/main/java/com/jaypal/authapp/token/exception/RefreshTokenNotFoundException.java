package com.jaypal.authapp.token.exception;

public class RefreshTokenNotFoundException extends RefreshTokenException {
    public RefreshTokenNotFoundException() {
        super("Refresh token not found");
    }
}
