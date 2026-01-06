package com.jaypal.authapp.common.exception.email;

import com.jaypal.authapp.common.exception.base.SecurityException;

public class VerificationTokenExpiredException extends SecurityException {
    public VerificationTokenExpiredException() {
        super("Verification token expired");
    }
}
