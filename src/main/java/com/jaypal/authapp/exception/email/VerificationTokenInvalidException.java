package com.jaypal.authapp.exception.email;

import com.jaypal.authapp.exception.base.SecurityException;

public class VerificationTokenInvalidException extends SecurityException {
    public VerificationTokenInvalidException() {
        super("Verification token invalid");
    }
}
