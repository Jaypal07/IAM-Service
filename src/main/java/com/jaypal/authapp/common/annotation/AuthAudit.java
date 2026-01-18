package com.jaypal.authapp.common.annotation;

import com.jaypal.authapp.domain.audit.entity.AuthAuditEvent;
import com.jaypal.authapp.domain.audit.entity.AuditSubjectType;
import com.jaypal.authapp.domain.audit.entity.AuthProvider;

import java.lang.annotation.*;

@Target(ElementType.METHOD)
@Retention(RetentionPolicy.RUNTIME)
@Documented
public @interface AuthAudit {

    AuthAuditEvent event();

    AuditSubjectType subject();

    AuthProvider provider() default AuthProvider.SYSTEM;
    /**
     * REQUIRED when subject is EMAIL or USER_ID.
     * Name of the method parameter that carries the subject.
     */
    String subjectParam() default "";
}
