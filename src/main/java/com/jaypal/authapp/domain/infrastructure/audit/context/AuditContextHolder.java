package com.jaypal.authapp.domain.infrastructure.audit.context;

import com.jaypal.authapp.domain.dto.audit.AuditRequestContext;
import org.springframework.core.task.TaskDecorator;
import org.springframework.lang.NonNull;

public final class AuditContextHolder {

    private static final ThreadLocal<AuditRequestContext> CONTEXT = new ThreadLocal<>();

    private AuditContextHolder() {
        throw new UnsupportedOperationException("Utility class");
    }

    public static void setContext(AuditRequestContext context) {
        CONTEXT.set(context);
    }

    public static AuditRequestContext getContext() {
        return CONTEXT.get();
    }

    public static void clear() {
        CONTEXT.remove();
    }

    public static class ContextCopyingDecorator implements TaskDecorator {
        @Override
        @NonNull
        public Runnable decorate(@NonNull Runnable task) {
            final AuditRequestContext context = AuditContextHolder.getContext();

            return () -> {
                try {
                    AuditContextHolder.setContext(context);
                    task.run();
                } finally {
                    AuditContextHolder.clear();
                }
            };
        }
    }
}