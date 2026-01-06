package com.jaypal.authapp.common.exception.refresh;

public class RefreshTokenUserMismatchException extends RefreshTokenException {
    public RefreshTokenUserMismatchException() {
        super("Refresh token user mismatch");
    }
}
