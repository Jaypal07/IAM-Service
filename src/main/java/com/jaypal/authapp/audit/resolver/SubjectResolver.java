package com.jaypal.authapp.audit.resolver;

import com.jaypal.authapp.audit.annotation.AuthAudit;
import com.jaypal.authapp.audit.context.AuditContext;
import com.jaypal.authapp.audit.domain.AuditSubjectType;
import com.jaypal.authapp.audit.domain.HasEmail;
import org.springframework.stereotype.Component;

@Component
public class SubjectResolver {

    public String resolve(AuthAudit authAudit, Object[] args) {

        if (authAudit.subject() != AuditSubjectType.EMAIL) {
            return null;
        }

        for (Object arg : args) {
            if (arg instanceof HasEmail e) {
                return e.getEmail();
            }
        }

        return AuditContext.getEmail();
    }
}
