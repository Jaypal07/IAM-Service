package com.jaypal.authapp.security.userdetails;

import com.jaypal.authapp.security.principal.AuthPrincipal;
import com.jaypal.authapp.user.application.PermissionService;
import com.jaypal.authapp.user.model.User;
import com.jaypal.authapp.user.repository.UserRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;

import java.util.HashSet;
import java.util.Set;

@Service
@RequiredArgsConstructor
public class CustomUserDetailService implements UserDetailsService {

    private final UserRepository userRepository;
    private final PermissionService permissionService;

    @Override
    public UserDetails loadUserByUsername(String email)
            throws UsernameNotFoundException {

        User user = userRepository.findByEmailWithRoles(email)
                .orElseThrow(() ->
                        new UsernameNotFoundException("Invalid username or password"));

        if (!user.isEnabled()) {
            throw new UsernameNotFoundException("User is disabled");
        }

        Set<GrantedAuthority> authorities = new HashSet<>();

        user.getRoles().forEach(role ->
                authorities.add(new SimpleGrantedAuthority(role))
        );

        permissionService.resolvePermissions(user.getId()).stream()
                .map(Enum::name)
                .map(SimpleGrantedAuthority::new)
                .forEach(authorities::add);

        return new AuthPrincipal(
                user.getId(),
                user.getEmail(),
                user.getPassword(),
                true,
                authorities
        );
    }
}
