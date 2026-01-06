package com.jaypal.authapp.common.exception.user;

import com.jaypal.authapp.common.exception.base.SecurityException;

public class PasswordResetTokenInvalidException extends SecurityException {
    public PasswordResetTokenInvalidException() {
        super("Password reset token invalid");
    }
}
