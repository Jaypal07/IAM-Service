package com.jaypal.authapp.dtos;

public record LoginRequest(
        String email,
        String password
) {
}
