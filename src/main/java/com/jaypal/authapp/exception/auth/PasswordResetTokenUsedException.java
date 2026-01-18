package com.jaypal.authapp.exception.auth;

public class PasswordResetTokenUsedException extends RuntimeException {
    public PasswordResetTokenUsedException(String message) {
        super(message);
    }
}
