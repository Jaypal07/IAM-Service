package com.jaypal.authapp.domain.audit.repository;

import com.jaypal.authapp.domain.audit.entity.AuthAuditLog;
import org.springframework.data.repository.Repository;

import java.util.UUID;

public interface AuthAuditRepository extends Repository<AuthAuditLog, UUID> {
    AuthAuditLog save(AuthAuditLog log);
    long count();
}
