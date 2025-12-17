package com.jaypal.authapp.dto;

public record LoginRequest(
        String email,
        String password
) {
}
