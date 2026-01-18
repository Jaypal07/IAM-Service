package com.jaypal.authapp.domain.token.exception;

public class RefreshTokenReuseDetectedException extends RefreshTokenException {
    public RefreshTokenReuseDetectedException() {
        super("Reuse refresh token");
    }
}
