package com.jaypal.authapp.dto;

public record ResetPasswordRequest(
        String token,
        String newPassword
) {}
