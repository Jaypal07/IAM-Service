package com.jaypal.authapp.audit.persistence;

import org.springframework.data.jpa.repository.JpaRepository;

import java.util.UUID;

public interface AuthAuditRepository
        extends JpaRepository<AuthAuditLog, UUID> {
}
