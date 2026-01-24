package com.jaypal.authapp.infrastructure.audit.state;

import com.jaypal.authapp.domain.audit.entity.AuditOutcome;
import com.jaypal.authapp.exception.auth.BusinessRejectionException;
import com.jaypal.authapp.exception.auth.IdempotentNoOpException;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Component;

@Slf4j
@Component
public class AuditStateMachine implements AuditOutcomePolicy {

    @Override
    public AuditOutcome resolve(AuditSignal signal) {

        // 1️⃣ Explicit intent ALWAYS wins
        if (signal.explicitRejection()) {
            log.debug("AuditStateMachine → REJECTION (explicit)");
            return AuditOutcome.REJECTION;
        }

        if (signal.explicitNoOp()) {
            log.debug("AuditStateMachine → NO_OP (explicit)");
            return AuditOutcome.NO_OP;
        }

        // 2️⃣ Exception path
        if (signal.exception() != null) {

            if (signal.exception() instanceof BusinessRejectionException) {
                log.debug(
                        "AuditStateMachine → REJECTION (business exception={})",
                        signal.exception().getClass().getSimpleName()
                );
                return AuditOutcome.REJECTION;
            }

            if (signal.exception() instanceof IdempotentNoOpException) {
                log.debug(
                        "AuditStateMachine → NO_OP (idempotent exception={})",
                        signal.exception().getClass().getSimpleName()
                );
                return AuditOutcome.NO_OP;
            }

            log.debug(
                    "AuditStateMachine → FAILURE (system exception={})",
                    signal.exception().getClass().getSimpleName()
            );
            return AuditOutcome.FAILURE;
        }

        // 3️⃣ Return-based NO_OP
        if (signal.result() == null ||
                (signal.result() instanceof Boolean b && !b)) {

            log.debug("AuditStateMachine → NO_OP (result-based)");
            return AuditOutcome.NO_OP;
        }

        // 4️⃣ Success
        log.debug("AuditStateMachine → SUCCESS");
        return AuditOutcome.SUCCESS;
    }
}
