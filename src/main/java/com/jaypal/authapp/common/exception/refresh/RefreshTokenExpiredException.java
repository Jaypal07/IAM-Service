package com.jaypal.authapp.common.exception.refresh;

public class RefreshTokenExpiredException extends RefreshTokenException {
    public RefreshTokenExpiredException() {
        super("Refresh token expired");
    }
}
