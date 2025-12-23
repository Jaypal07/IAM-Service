package com.jaypal.authapp.audit.service;

import com.jaypal.authapp.audit.model.AuthAuditEvent;
import com.jaypal.authapp.audit.model.AuthAuditLog;
import com.jaypal.authapp.audit.repository.AuthAuditRepository;
import jakarta.servlet.http.HttpServletRequest;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Service;

import java.util.UUID;

@Service
@RequiredArgsConstructor
public class AuthAuditService {

    private final AuthAuditRepository repository;

    public void log(
            UUID userId,
            AuthAuditEvent event,
            String provider,
            HttpServletRequest request,
            boolean success,
            String reason
    ) {

        repository.save(
                AuthAuditLog.builder()
                        .userId(userId)
                        .eventType(event)
                        .provider(provider)
                        .success(success)
                        .reason(reason)
                        .ipAddress(extractIp(request))
                        .userAgent(request.getHeader("User-Agent"))
                        .build()
        );
    }

    private String extractIp(HttpServletRequest request) {
        String forwarded = request.getHeader("X-Forwarded-For");
        if (forwarded != null && !forwarded.isBlank()) {
            return forwarded.split(",")[0].trim();
        }
        return request.getRemoteAddr();
    }
}
