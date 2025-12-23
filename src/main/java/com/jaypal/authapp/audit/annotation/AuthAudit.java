package com.jaypal.authapp.audit.annotation;

import com.jaypal.authapp.audit.model.AuthAuditEvent;

import java.lang.annotation.*;

@Target(ElementType.METHOD)
@Retention(RetentionPolicy.RUNTIME)
@Documented
public @interface AuthAudit {

    AuthAuditEvent event();
    String provider() default "LOCAL";
}
