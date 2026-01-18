package com.jaypal.authapp.exception.auth;

import com.jaypal.authapp.exception.SecurityException;

public class VerificationTokenExpiredException extends SecurityException {
    public VerificationTokenExpiredException() {
        super("Verification token expired");
    }
}
