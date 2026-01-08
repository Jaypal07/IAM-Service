package com.jaypal.authapp.user.repository;

import com.jaypal.authapp.user.model.*;
import org.springframework.data.jpa.repository.JpaRepository;

import java.util.UUID;

public interface UserRoleRepository extends JpaRepository<UserRole, UUID> {

    boolean existsByUserAndRole(User user, Role role);

    void deleteByUserAndRole(User user, Role role);
}
