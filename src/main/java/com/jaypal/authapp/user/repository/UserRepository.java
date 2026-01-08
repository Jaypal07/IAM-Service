package com.jaypal.authapp.user.repository;

import com.jaypal.authapp.user.model.Provider;
import com.jaypal.authapp.user.model.User;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;
import org.springframework.stereotype.Repository;

import java.util.Optional;
import java.util.UUID;

@Repository
public interface UserRepository extends JpaRepository<User, UUID> {
    Optional<User> findByEmail(String email);
    boolean existsByEmail(String email);
    Optional<User> findByProviderAndProviderId(Provider provider, String providerId);
    @Query("""
        select distinct u
        from User u
        left join fetch u.userRoles ur
        left join fetch ur.role r
        where u.email = :email
    """)
    Optional<User> findByEmailWithRoles(String email);

    @Query("""
    select distinct u
    from User u
    left join fetch u.userRoles ur
    left join fetch ur.role
    where u.id = :id
    """)
    Optional<User> findByIdWithRoles(UUID id);

    @Query("""
    select u.permissionVersion
    from User u
    where u.id = :userId
    """)
    Optional<Long> findPermissionVersionById(UUID userId);


}
