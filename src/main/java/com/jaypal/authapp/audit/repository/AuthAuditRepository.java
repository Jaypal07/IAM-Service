package com.jaypal.authapp.audit.repository;

import com.jaypal.authapp.audit.model.AuthAuditLog;
import org.springframework.data.jpa.repository.JpaRepository;

import java.util.UUID;

public interface AuthAuditRepository
        extends JpaRepository<AuthAuditLog, UUID> {
}
