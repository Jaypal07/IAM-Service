package com.jaypal.authapp.audit.application;

import com.jaypal.authapp.audit.domain.AuthAuditEvent;
import com.jaypal.authapp.audit.domain.AuthFailureReason;
import com.jaypal.authapp.audit.persistence.AuthAuditLog;
import com.jaypal.authapp.audit.persistence.AuthAuditRepository;
import com.jaypal.authapp.audit.validation.AuthAuditMatrix;
import jakarta.servlet.http.HttpServletRequest;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Service;

import java.util.UUID;

@Service
@RequiredArgsConstructor
@Slf4j
public class AuthAuditService {

    private final AuthAuditRepository repository;

    public void log(
            UUID userId,
            String subject,
            AuthAuditEvent event,
            String provider,
            HttpServletRequest request,
            boolean success,
            AuthFailureReason failureReason
    ) {
        try {

            if (!success && !AuthAuditMatrix.isAllowed(event, failureReason)) {
                failureReason = AuthFailureReason.SYSTEM_ERROR;
            }

            repository.save(
                    AuthAuditLog.builder()
                            .userId(userId)
                            .subject(subject)
                            .eventType(event)
                            .provider(provider)
                            .success(success)
                            .failureReason(success ? null : failureReason)
                            .ipAddress(extractIp(request))
                            .userAgent(
                                    request != null
                                            ? request.getHeader("User-Agent")
                                            : null
                            )
                            .build()
            );

        } catch (Exception ex) {
            log.error(
                    "Audit logging failed. event={}, success={}",
                    event, success, ex
            );
        }
    }

    private String extractIp(HttpServletRequest request) {
        if (request == null) {
            return null;
        }
        String forwarded = request.getHeader("X-Forwarded-For");
        if (forwarded != null && !forwarded.isBlank()) {
            return forwarded.split(",")[0].trim();
        }
        return request.getRemoteAddr();
    }
}
