package com.jaypal.authapp.domain.user.repository;

import com.jaypal.authapp.domain.user.entity.Role;
import com.jaypal.authapp.domain.user.entity.RoleType;
import org.springframework.data.jpa.repository.JpaRepository;

import java.util.Optional;
import java.util.UUID;

public interface RoleRepository extends JpaRepository<Role, UUID> {

    Optional<Role> findByType(RoleType type);
}
