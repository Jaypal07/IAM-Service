package com.jaypal.authapp.domain.token.exception;

public class RefreshTokenRevokedException extends RefreshTokenException {
    public RefreshTokenRevokedException() {
        super("Refresh token revoked");
    }
}
