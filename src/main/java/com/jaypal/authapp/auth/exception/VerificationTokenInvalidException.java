package com.jaypal.authapp.auth.exception;

import com.jaypal.authapp.shared.exception.SecurityException;

public class VerificationTokenInvalidException extends SecurityException {
    public VerificationTokenInvalidException() {
        super("Verification token invalid");
    }
}
