package com.jaypal.authapp.common.exception.email;

import com.jaypal.authapp.common.exception.base.DomainException;

public class EmailAlreadyVerifiedException extends DomainException {
    public EmailAlreadyVerifiedException() {
        super("Email already verified");
    }
}
