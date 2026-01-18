package com.jaypal.authapp.infrastructure.oauth.handler;

public class OAuthAuthenticationException extends RuntimeException {
    public OAuthAuthenticationException(String message) {
        super(message);
    }
}
