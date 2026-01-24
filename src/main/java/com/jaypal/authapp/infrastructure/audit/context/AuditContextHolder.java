package com.jaypal.authapp.infrastructure.audit.context;

import com.jaypal.authapp.domain.audit.entity.AuthFailureReason;
import com.jaypal.authapp.dto.audit.AuditRequestContext;
import org.springframework.core.task.TaskDecorator;
import org.springframework.lang.NonNull;

public final class AuditContextHolder {

    private static final ThreadLocal<AuditRequestContext> CONTEXT = new ThreadLocal<>();

    private static final ThreadLocal<Boolean> NO_OP = ThreadLocal.withInitial(() -> false);

    private static final ThreadLocal<Boolean> REJECTION = ThreadLocal.withInitial(() -> false);

    private static final ThreadLocal<AuthFailureReason> REJECTION_REASON = new ThreadLocal<>();

    private AuditContextHolder() {
        throw new UnsupportedOperationException("Utility class");
    }

    /* ===================== Context ===================== */

    public static void setContext(AuditRequestContext context) {
        if (context == null) {
            CONTEXT.remove();
        } else {
            CONTEXT.set(context);
        }
    }

    public static AuditRequestContext getContext() {
        return CONTEXT.get();
    }

    /* ===================== Outcome APIs ===================== */

    public static void markNoOp() {
        if (!isRejection()) {
            NO_OP.set(true);
        }
    }

    public static boolean isNoOp() {
        return Boolean.TRUE.equals(NO_OP.get());
    }

    public static void markRejection(@NonNull AuthFailureReason reason) {
        REJECTION.set(true);
        REJECTION_REASON.set(reason);
        NO_OP.remove(); // rejection always wins
    }

    public static boolean isRejection() {
        return Boolean.TRUE.equals(REJECTION.get());
    }

    public static AuthFailureReason getRejectionReason() {
        return REJECTION_REASON.get();
    }

    public static void markSuccess() {
        NO_OP.remove();
        REJECTION.remove();
        REJECTION_REASON.remove();
    }

    /* ===================== Cleanup ===================== */

    public static void clear() {
        CONTEXT.remove();
        NO_OP.remove();
        REJECTION.remove();
        REJECTION_REASON.remove();
    }

    /* ===================== Async propagation ===================== */

    public static class ContextCopyingDecorator implements TaskDecorator {

        @Override
        @NonNull
        public Runnable decorate(@NonNull Runnable task) {
            final AuditRequestContext context = getContext();
            final boolean noOp = isNoOp();
            final boolean rejection = isRejection();
            final AuthFailureReason reason = getRejectionReason();

            return () -> {
                try {
                    setContext(context);
                    if (noOp) {
                        markNoOp();
                    }

                    if (rejection) {
                        markRejection(reason);
                    }
                    task.run();
                } finally {
                    clear();
                }
            };
        }
    }
}
