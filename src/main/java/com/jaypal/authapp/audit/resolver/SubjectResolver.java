package com.jaypal.authapp.audit.resolver;

import com.jaypal.authapp.audit.annotation.AuthAudit;
import com.jaypal.authapp.audit.domain.AuditSubject;
import com.jaypal.authapp.audit.domain.AuditSubjectType;
import com.jaypal.authapp.audit.domain.HasEmail;
import com.jaypal.authapp.security.principal.AuthPrincipal;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Component;

import java.util.Objects;

@Slf4j
@Component
public class SubjectResolver {

    public AuditSubject resolve(
            AuthAudit annotation,
            Object[] args,
            String[] paramNames
    ) {
        try {
            Objects.requireNonNull(annotation, "annotation must not be null");
            Objects.requireNonNull(args, "args must not be null");
            Objects.requireNonNull(paramNames, "paramNames must not be null");

            AuditSubjectType type = annotation.subject();

            // Explicit subject types
            if (type == AuditSubjectType.ANONYMOUS) {
                return AuditSubject.anonymous();
            }

            if (type == AuditSubjectType.SYSTEM) {
                return AuditSubject.system();
            }

            // Param-based subject types
            if (annotation.subjectParam().isBlank()) {
                log.warn("Audit subjectParam is blank for subject type {}", type);
                return AuditSubject.anonymous();
            }

            for (int i = 0; i < paramNames.length; i++) {
                if (annotation.subjectParam().equals(paramNames[i])) {
                    Object value = args[i];

                    if (value == null) {
                        log.warn("Audit subject parameter '{}' is null", paramNames[i]);
                        return AuditSubject.anonymous();
                    }

                    return extractSubject(type, value);
                }
            }

            log.warn("Audit subject parameter '{}' not found", annotation.subjectParam());
            return AuditSubject.anonymous();

        } catch (Exception ex) {
            // Absolute safety net — audit must never fail the request
            log.warn("Audit subject resolution failed, defaulting to ANONYMOUS", ex);
            return AuditSubject.anonymous();
        }
    }

    private AuditSubject extractSubject(AuditSubjectType type, Object value) {
        return switch (type) {
            case EMAIL, IP -> extractEmail(value);
            case USER_ID -> extractUserId(value);
            case ANONYMOUS, SYSTEM -> {
                log.warn("Subject type {} should not require extraction", type);
                yield AuditSubject.anonymous();
            }
        };
    }

    private AuditSubject extractEmail(Object value) {
        try {
            String email = null;

            if (value instanceof String str) {
                email = str;
            } else if (value instanceof HasEmail hasEmail) {
                email = hasEmail.getEmail();
            } else if (value instanceof AuthPrincipal principal) {
                email = principal.getEmail();
            } else {
                log.warn("Cannot extract email from type: {}", value.getClass().getName());
                return AuditSubject.anonymous();
            }

            if (email == null || email.isBlank()) {
                log.warn("Extracted email is blank");
                return AuditSubject.anonymous();
            }

            return AuditSubject.email(email);

        } catch (Exception ex) {
            log.warn("Email extraction failed, defaulting to ANONYMOUS", ex);
            return AuditSubject.anonymous();
        }
    }

    private AuditSubject extractUserId(Object value) {
        try {
            String userId = null;

            if (value instanceof String str) {
                userId = str;
            } else if (value instanceof AuthPrincipal principal) {
                if (principal.getUserId() != null) {
                    userId = principal.getUserId().toString();
                }
            } else {
                log.warn("Cannot extract user ID from type: {}", value.getClass().getName());
                return AuditSubject.anonymous();
            }

            if (userId == null || userId.isBlank()) {
                log.warn("Extracted user ID is blank");
                return AuditSubject.anonymous();
            }

            return AuditSubject.userId(userId);

        } catch (Exception ex) {
            log.warn("User ID extraction failed, defaulting to ANONYMOUS", ex);
            return AuditSubject.anonymous();
        }
    }
}
