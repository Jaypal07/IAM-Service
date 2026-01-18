package com.jaypal.authapp.domain.token.exception;

public class RefreshTokenUserMismatchException extends RefreshTokenException {
    public RefreshTokenUserMismatchException() {
        super("Refresh token user mismatch");
    }
}
