package com.jaypal.authapp.domain.user.repository;

import com.jaypal.authapp.domain.user.entity.Permission;
import com.jaypal.authapp.domain.user.entity.PermissionType;
import com.jaypal.authapp.domain.user.entity.Role;
import com.jaypal.authapp.domain.user.entity.RolePermission;
import com.jaypal.authapp.user.model.*;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;

import java.util.Set;
import java.util.UUID;

public interface RolePermissionRepository extends JpaRepository<RolePermission, UUID> {

    Set<RolePermission> findByRole(Role role);
    boolean existsByRoleAndPermission(Role role, Permission permission);

    @Query("""
    select rp.permission.type
    from RolePermission rp
    where rp.role = :role
    """)
    Set<PermissionType> findPermissionTypesByRole(@Param("role") Role role);

}
