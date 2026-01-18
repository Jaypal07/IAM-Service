package com.jaypal.authapp.exception.auth;

import com.jaypal.authapp.exception.SecurityException;

public class VerificationTokenInvalidException extends SecurityException {
    public VerificationTokenInvalidException() {
        super("Verification token invalid");
    }
}
