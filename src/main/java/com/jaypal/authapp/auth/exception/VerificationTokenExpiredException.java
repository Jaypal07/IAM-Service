package com.jaypal.authapp.auth.exception;

import com.jaypal.authapp.shared.exception.SecurityException;

public class VerificationTokenExpiredException extends SecurityException {
    public VerificationTokenExpiredException() {
        super("Verification token expired");
    }
}
