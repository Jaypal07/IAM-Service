package com.jaypal.authapp.dto;

import com.fasterxml.jackson.annotation.JsonInclude;
import java.time.LocalDateTime;
import java.util.Map;

@JsonInclude(JsonInclude.Include.NON_NULL)
public record ErrorResponse(
        String path,
        int status,
        String error, // e.g., "Bad Request", "Internal Server Error"
        String message, // A user-friendly message
        LocalDateTime timestamp,
        // Optional: for validation errors, holds specific field errors (e.g., "email": "must be valid")
        Map<String, String> details,
        // Optional: a unique ID for the error used for debugging/logging purposes
        String traceId
) {
    public ErrorResponse(String path, int status, String error, String message) {
        this(path, status, error, message, LocalDateTime.now(), null, null);
    }
}
