package com.jaypal.authapp.domain.audit.entity;

import lombok.ToString;

import java.util.Objects;

@ToString
public final class AuditSubject {

    private final AuditSubjectType type;
    private final String identifier;

    private AuditSubject(AuditSubjectType type, String identifier) {
        this.type = Objects.requireNonNull(type);
        this.identifier = identifier;
    }

    public static AuditSubject anonymous() {
        return new AuditSubject(AuditSubjectType.ANONYMOUS, null);
    }

    public static AuditSubject system() {
        return new AuditSubject(AuditSubjectType.SYSTEM, "SYSTEM");
    }

    public static AuditSubject userId(String userId) {
        if (userId == null || userId.isBlank()) {
            throw new IllegalArgumentException("userId must not be blank");
        }
        return new AuditSubject(AuditSubjectType.USER_ID, userId);
    }

    public static AuditSubject email(String email) {
        if (email == null || email.isBlank()) {
            throw new IllegalArgumentException("email must not be blank");
        }
        return new AuditSubject(AuditSubjectType.EMAIL, email);
    }

    public AuditSubjectType getType() {
        return type;
    }

    public String getIdentifier() {
        return identifier;
    }
}
