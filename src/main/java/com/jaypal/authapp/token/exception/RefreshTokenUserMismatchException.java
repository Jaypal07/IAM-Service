package com.jaypal.authapp.token.exception;

public class RefreshTokenUserMismatchException extends RefreshTokenException {
    public RefreshTokenUserMismatchException() {
        super("Refresh token user mismatch");
    }
}
