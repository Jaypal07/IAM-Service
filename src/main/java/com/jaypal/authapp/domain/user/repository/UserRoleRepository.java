package com.jaypal.authapp.domain.user.repository;

import com.jaypal.authapp.domain.user.entity.Role;
import com.jaypal.authapp.domain.user.entity.User;
import com.jaypal.authapp.domain.user.entity.UserRole;
import com.jaypal.authapp.user.model.*;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;

import java.util.List;
import java.util.Set;
import java.util.UUID;

public interface UserRoleRepository extends JpaRepository<UserRole, UUID> {

    boolean existsByUserAndRole(User user, Role role);

    void deleteByUserAndRole(User user, Role role);

    @Query("""
        select distinct ur
        from UserRole ur
        join fetch ur.role r
        left join fetch r.rolePermissions rp
        left join fetch rp.permission
        where ur.user.id in :userIds
    """)
    List<UserRole> findAllWithRolesAndPermissions(
            @Param("userIds") Set<UUID> userIds
    );
}
