package com.jaypal.authapp.auth.exception;

import com.jaypal.authapp.shared.exception.DomainException;

public class PasswordPolicyViolationException extends DomainException {
    public PasswordPolicyViolationException(String s) {
        super(s);
    }
}
