package com.jaypal.authapp.exception.auth;

public class SilentEmailVerificationResendException extends RuntimeException {
    public SilentEmailVerificationResendException(String message) {
        super(message);
    }
}
