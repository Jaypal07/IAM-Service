package com.jaypal.authapp.exception.auth;

import com.jaypal.authapp.exception.DomainException;

public class EmailDeliveryException extends DomainException {
    public EmailDeliveryException(String message) {
        super(message);
    }
}
