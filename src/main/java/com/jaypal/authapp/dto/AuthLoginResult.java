package com.jaypal.authapp.dto;
import com.jaypal.authapp.user.model.User;

public record AuthLoginResult(
        User user,
        String accessToken,
        String refreshToken,
        long refreshTtlSeconds
) {}
