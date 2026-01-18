package com.jaypal.authapp.exception.auth;

import com.jaypal.authapp.exception.DomainException;

public class PasswordPolicyViolationException extends DomainException {
    public PasswordPolicyViolationException(String s) {
        super(s);
    }
}
