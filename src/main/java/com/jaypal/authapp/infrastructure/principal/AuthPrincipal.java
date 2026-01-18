package com.jaypal.authapp.infrastructure.principal;

import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;

import java.io.Serial;
import java.io.Serializable;
import java.util.Collection;
import java.util.Collections;
import java.util.Objects;
import java.util.UUID;

public final class AuthPrincipal implements UserDetails, Serializable {

    @Serial
    private static final long serialVersionUID = 1L;

    private final UUID userId;
    private final String email;
    private final String password;
    private final Collection<? extends GrantedAuthority> authorities;

    public AuthPrincipal(
            UUID userId,
            String email,
            String password,
            Collection<? extends GrantedAuthority> authorities
    ) {
        this.userId = Objects.requireNonNull(userId, "User ID cannot be null");
        this.email = Objects.requireNonNull(email, "Email cannot be null");
        this.password = password;
        this.authorities = authorities != null
                ? Collections.unmodifiableCollection(authorities)
                : Collections.emptySet();
    }

    public UUID getUserId() {
        return userId;
    }

    public String getEmail() {
        return email;
    }

    @Override
    public Collection<? extends GrantedAuthority> getAuthorities() {
        return authorities;
    }

    @Override
    public String getPassword() {
        return password;
    }

    @Override
    public String getUsername() {
        return email;
    }

    @Override
    public boolean isAccountNonExpired() {
        return true;
    }

    @Override
    public boolean isAccountNonLocked() {
        return true;
    }

    @Override
    public boolean isCredentialsNonExpired() {
        return true;
    }

    @Override
    public boolean isEnabled() {
        return true;
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (!(o instanceof AuthPrincipal that)) return false;
        return Objects.equals(userId, that.userId);
    }

    @Override
    public int hashCode() {
        return Objects.hash(userId);
    }

    @Override
    public String toString() {
        return "AuthPrincipal{userId=" + userId + ", email='" + email + "'}";
    }
}

/*
CHANGELOG:
1. Implemented Serializable for session storage compatibility
2. Added serialVersionUID for serialization stability
3. Added null checks for userId and email in constructor
4. Made authorities collection immutable
5. Added null handling for authorities parameter
6. Implemented equals() and hashCode() based on userId
7. Implemented toString() for debugging (without sensitive data)
8. Made class final to prevent inheritance issues
9. Added isEnabled() to return true (handled in UserDetailsService)
10. Used Collections.unmodifiableCollection for defensive copying
*/