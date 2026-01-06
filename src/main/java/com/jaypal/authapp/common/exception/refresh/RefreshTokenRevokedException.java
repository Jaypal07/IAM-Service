package com.jaypal.authapp.common.exception.refresh;

public class RefreshTokenRevokedException extends RefreshTokenException {
    public RefreshTokenRevokedException() {
        super("Refresh token revoked");
    }
}
