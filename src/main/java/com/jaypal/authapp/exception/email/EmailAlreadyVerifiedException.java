package com.jaypal.authapp.exception.email;

import com.jaypal.authapp.exception.base.DomainException;

public class EmailAlreadyVerifiedException extends DomainException {
    public EmailAlreadyVerifiedException() {
        super("Email already verified");
    }
}
