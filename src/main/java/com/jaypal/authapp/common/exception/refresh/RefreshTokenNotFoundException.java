package com.jaypal.authapp.common.exception.refresh;

public class RefreshTokenNotFoundException extends RefreshTokenException {
    public RefreshTokenNotFoundException() {
        super("Refresh token not found");
    }
}
