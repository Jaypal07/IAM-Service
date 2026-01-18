package com.jaypal.authapp.domain.user.repository;

import com.jaypal.authapp.domain.dto.user.UserResponseDto;
import com.jaypal.authapp.domain.user.entity.Provider;
import com.jaypal.authapp.domain.user.entity.User;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;
import org.springframework.stereotype.Repository;

import java.util.List;
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

    @Query("""
        select new com.jaypal.authapp.user.dto.UserResponseDto(
            u.id,
            u.email,
            u.name,
            u.image,
            u.enabled,
            u.provider,
            null,
            null,
            u.createdAt,
            u.updatedAt
        )
        from User u
    """)
    List<UserResponseDto> findAllBaseUsers();

    @Query("""
        select distinct u
        from User u
        left join fetch u.userRoles ur
        left join fetch ur.role
    """)
    List<User> findAllWithRoles();

}
