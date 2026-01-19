package com.jaypal.authapp.infrastructure.audit.context;

import com.jaypal.authapp.dto.audit.AuditRequestContext;
import org.springframework.core.task.TaskDecorator;
import org.springframework.lang.NonNull;

public final class AuditContextHolder {

    private static final ThreadLocal<AuditRequestContext> CONTEXT = new ThreadLocal<>();
    private static final ThreadLocal<Boolean> NO_OP = new ThreadLocal<>();

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
        NO_OP.remove();
    }

    public static void markNoOp() {
        NO_OP.set(true);
    }

    public static boolean isNoOp() {
        Boolean val = NO_OP.get();
        return val != null && val;
    }

    public static class ContextCopyingDecorator implements TaskDecorator {
        @Override
        @NonNull
        public Runnable decorate(@NonNull Runnable task) {
            final AuditRequestContext context = AuditContextHolder.getContext();
            final boolean noOp = AuditContextHolder.isNoOp();

            return () -> {
                try {
                    AuditContextHolder.setContext(context);
                    if (noOp) markNoOp();
                    task.run();
                } finally {
                    AuditContextHolder.clear();
                }
            };
        }
    }
}