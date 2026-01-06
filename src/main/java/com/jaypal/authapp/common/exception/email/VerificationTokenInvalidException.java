package com.jaypal.authapp.common.exception.email;

import com.jaypal.authapp.common.exception.base.SecurityException;

public class VerificationTokenInvalidException extends SecurityException {
    public VerificationTokenInvalidException() {
        super("Verification token invalid");
    }
}
