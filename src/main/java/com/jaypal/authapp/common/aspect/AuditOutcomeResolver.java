package com.jaypal.authapp.common.aspect;

import com.jaypal.authapp.domain.audit.entity.AuditOutcome;
import com.jaypal.authapp.infrastructure.audit.context.AuditContextHolder;
import com.jaypal.authapp.infrastructure.audit.state.AuditOutcomePolicy;
import com.jaypal.authapp.infrastructure.audit.state.AuditSignal;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Component;

@Slf4j
@Component
@RequiredArgsConstructor
public class AuditOutcomeResolver {

    private final AuditOutcomePolicy stateMachine;

    public AuditOutcome fromResult(Object result) {
        return stateMachine.resolve(
                new AuditSignal(
                        result,
                        null,
                        AuditContextHolder.isNoOp(),
                        AuditContextHolder.isRejection()
                )
        );
    }

    public AuditOutcome fromException(Throwable ex) {
        return stateMachine.resolve(
                new AuditSignal(
                        null,
                        ex,
                        AuditContextHolder.isNoOp(),
                        AuditContextHolder.isRejection()
                )
        );
    }
}
