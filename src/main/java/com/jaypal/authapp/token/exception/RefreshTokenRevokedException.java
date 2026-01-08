package com.jaypal.authapp.token.exception;

public class RefreshTokenRevokedException extends RefreshTokenException {
    public RefreshTokenRevokedException() {
        super("Refresh token revoked");
    }
}
