package com.jaypal.authapp.auth.exception;

public class EmailDeliveryFailedException extends RuntimeException {

    public EmailDeliveryFailedException(String message, Throwable cause) {
        super(message, cause);
    }

    public EmailDeliveryFailedException(String message) {
        super(message);
    }
}
