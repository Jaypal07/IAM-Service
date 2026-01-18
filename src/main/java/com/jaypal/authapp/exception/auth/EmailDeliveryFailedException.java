package com.jaypal.authapp.exception.auth;

public class EmailDeliveryFailedException extends RuntimeException {

    public EmailDeliveryFailedException(String message, Throwable cause) {
        super(message, cause);
    }

    public EmailDeliveryFailedException(String message) {
        super(message);
    }
}
