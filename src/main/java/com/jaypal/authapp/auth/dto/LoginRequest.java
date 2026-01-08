package com.jaypal.authapp.auth.dto;

import com.jaypal.authapp.audit.domain.HasEmail;

public record LoginRequest(
        String email,
        String password
) implements HasEmail {

    @Override
    public String getEmail() {
        return email;
    }
}
