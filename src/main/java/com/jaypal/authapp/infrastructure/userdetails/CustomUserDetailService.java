package com.jaypal.authapp.infrastructure.userdetails;

import com.jaypal.authapp.exception.auth.SilentEmailVerificationResendException;
import com.jaypal.authapp.infrastructure.principal.AuthPrincipal;
import com.jaypal.authapp.domain.user.service.PermissionService;
import com.jaypal.authapp.domain.user.entity.User;
import com.jaypal.authapp.domain.user.repository.UserRepository;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.authentication.DisabledException;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.*;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.util.Objects;
import java.util.Set;
import java.util.stream.Collectors;

@Slf4j
@Service
@RequiredArgsConstructor
public class CustomUserDetailService implements UserDetailsService {

    private final UserRepository userRepository;
    private final PermissionService permissionService;

    @Override
    @Transactional(readOnly = true)
    public UserDetails loadUserByUsername(String email) throws UsernameNotFoundException {
        Objects.requireNonNull(email, "Email cannot be null");

        if (email.isBlank()) {
            log.warn("Login attempt with blank email");
            throw new UsernameNotFoundException("Invalid credentials");
        }

        final User user = userRepository.findByEmailWithRoles(email)
                .orElseThrow(() -> {
                    log.warn("Login attempt for non-existent email: {}", maskEmail(email));
                    return new UsernameNotFoundException("Invalid credentials");
                });

        if (!user.isEnabled()) {
            log.warn("Login attempt for disabled user: {}", user.getId());
            throw new DisabledException("Account is disabled");
        }

        if (!user.isEmailVerified()) {
            log.warn("Login attempt for unverified user: {}", user.getId());
            throw new SilentEmailVerificationResendException(
                    "Resend verification requested for unverified email: " + email
            );
        }

        final Set<String> permissionNames = permissionService.resolvePermissions(user.getId())
                .stream()
                .map(Enum::name)
                .collect(Collectors.toSet());

        user.getRoles().forEach(role ->
                permissionNames.add("ROLE_" + role)
        );

        final Set<SimpleGrantedAuthority> authorities = permissionNames.stream()
                .map(SimpleGrantedAuthority::new)
                .collect(Collectors.toSet());

        log.debug("User loaded successfully: {} with {} authorities", user.getId(), authorities.size());

        return new AuthPrincipal(
                user.getId(),
                user.getEmail(),
                user.getPassword(),
                authorities
        );
    }

    private String maskEmail(String email) {
        if (email == null || email.length() <= 3) {
            return "***";
        }

        final int atIndex = email.indexOf('@');
        if (atIndex <= 0) {
            return email.substring(0, 2) + "***";
        }

        return email.substring(0, Math.min(2, atIndex)) + "***" + email.substring(atIndex);
    }
}
