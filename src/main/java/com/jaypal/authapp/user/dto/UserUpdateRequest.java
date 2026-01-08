package com.jaypal.authapp.user.dto;

public record UserUpdateRequest(
        String name,
        String image,
        String password
) {}
