package com.jaypal.authapp.user.repository;

import com.jaypal.authapp.user.model.Role;
import com.jaypal.authapp.user.model.RoleType;
import org.springframework.data.jpa.repository.JpaRepository;

import java.util.Optional;
import java.util.UUID;

public interface RoleRepository extends JpaRepository<Role, UUID> {

    Optional<Role> findByType(RoleType type);
}
