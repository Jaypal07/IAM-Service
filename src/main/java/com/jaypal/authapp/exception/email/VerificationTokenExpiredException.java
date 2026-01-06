package com.jaypal.authapp.exception.email;

import com.jaypal.authapp.exception.base.SecurityException;

public class VerificationTokenExpiredException extends SecurityException {
    public VerificationTokenExpiredException() {
        super("Verification token expired");
    }
}
