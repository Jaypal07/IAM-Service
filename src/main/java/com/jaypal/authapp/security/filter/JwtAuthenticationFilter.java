package com.jaypal.authapp.security.filter;

import com.jaypal.authapp.security.jwt.JwtService;
import com.jaypal.authapp.security.principal.AuthPrincipal;
import com.jaypal.authapp.user.model.User;
import com.jaypal.authapp.user.repository.UserRepository;
import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jws;
import io.jsonwebtoken.JwtException;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.web.authentication.WebAuthenticationDetailsSource;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;
import java.util.HashSet;
import java.util.Set;
import java.util.UUID;

@Component
@RequiredArgsConstructor
public class JwtAuthenticationFilter extends OncePerRequestFilter {

    private final JwtService jwtService;
    private final UserRepository userRepository;

    @Override
    protected void doFilterInternal(
            HttpServletRequest request,
            HttpServletResponse response,
            FilterChain chain
    ) throws ServletException, IOException {

        String header = request.getHeader("Authorization");

        if (header == null || !header.startsWith("Bearer ")) {
            chain.doFilter(request, response);
            return;
        }

        Jws<Claims> parsed;
        try {
            parsed = jwtService.parse(header.substring(7).trim());
        } catch (JwtException ex) {
            chain.doFilter(request, response);
            return;
        }

        if (!jwtService.isAccessToken(parsed)) {
            chain.doFilter(request, response);
            return;
        }

        if (SecurityContextHolder.getContext().getAuthentication() != null) {
            chain.doFilter(request, response);
            return;
        }

        Claims claims = parsed.getBody();
        UUID userId = jwtService.extractUserId(claims);
        long tokenPv = jwtService.extractPermissionVersion(claims);

        long currentPv = userRepository
                .findPermissionVersionById(userId)
                .orElse(-1L);

        if (tokenPv != currentPv) {
            chain.doFilter(request, response);
            return;
        }

        Set<GrantedAuthority> authorities = new HashSet<>();

        jwtService.extractRoles(claims).forEach(role ->
                authorities.add(new SimpleGrantedAuthority(role))
        );

        jwtService.extractPermissions(claims).forEach(perm ->
                authorities.add(new SimpleGrantedAuthority(perm))
        );

        AuthPrincipal principal = new AuthPrincipal(
                userId,
                jwtService.extractEmail(claims),
                null,
                true,
                authorities
        );

        UsernamePasswordAuthenticationToken authentication =
                new UsernamePasswordAuthenticationToken(
                        principal,
                        null,
                        authorities
                );

        authentication.setDetails(
                new WebAuthenticationDetailsSource().buildDetails(request)
        );

        SecurityContextHolder.getContext().setAuthentication(authentication);
        chain.doFilter(request, response);
    }

    @Override
    protected boolean shouldNotFilter(HttpServletRequest request) {
        String path = request.getRequestURI();
        return path.equals("/api/v1/auth/login")
                || path.equals("/api/v1/auth/register");
    }
}
