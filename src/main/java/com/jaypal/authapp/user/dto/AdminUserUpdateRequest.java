package com.jaypal.authapp.user.dto;

public record AdminUserUpdateRequest(
        String name,
        String image,
        Boolean enabled
) {}
