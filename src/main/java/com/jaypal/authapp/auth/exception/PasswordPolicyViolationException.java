package com.jaypal.authapp.auth.exception;

import com.jaypal.authapp.shared.exception.DomainException;

public class PasswordPolicyViolationException extends DomainException {
    public PasswordPolicyViolationException() {
        super("Password too short");
    }
}
