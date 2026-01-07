package com.jaypal.authapp.user.repository;

import com.jaypal.authapp.user.model.*;
import org.springframework.data.jpa.repository.JpaRepository;

import java.util.Set;
import java.util.UUID;

public interface RolePermissionRepository extends JpaRepository<RolePermission, UUID> {

    Set<RolePermission> findByRole(Role role);
    boolean existsByRoleAndPermission(Role role, Permission permission);
}
