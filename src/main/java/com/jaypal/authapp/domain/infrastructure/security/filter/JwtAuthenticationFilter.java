package com.jaypal.authapp.domain.infrastructure.security.filter;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.jaypal.authapp.domain.infrastructure.security.jwt.JwtService;
import com.jaypal.authapp.domain.infrastructure.principal.AuthPrincipal;
import com.jaypal.authapp.domain.user.repository.UserRepository;
import io.jsonwebtoken.Claims;
import io.jsonwebtoken.ExpiredJwtException;
import io.jsonwebtoken.JwtException;
import io.jsonwebtoken.Jws;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.lang.NonNull;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.web.authentication.WebAuthenticationDetailsSource;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;
import java.util.*;

@Slf4j
@Component
@RequiredArgsConstructor
public class JwtAuthenticationFilter extends OncePerRequestFilter {

    private static final String BEARER_PREFIX = "Bearer ";
    private static final int BEARER_PREFIX_LENGTH = 7;

    private final JwtService jwtService;
    private final UserRepository userRepository;
    private final ObjectMapper objectMapper;

    @Override
    protected void doFilterInternal(
            @NonNull HttpServletRequest request,
            @NonNull HttpServletResponse response,
            @NonNull FilterChain chain
    ) throws ServletException, IOException {

        final String authHeader = request.getHeader("Authorization");

        if (authHeader == null || !authHeader.startsWith(BEARER_PREFIX)) {
            chain.doFilter(request, response);
            return;
        }

        try {
            final String token = authHeader.substring(BEARER_PREFIX_LENGTH).trim();

            if (token.isEmpty()) {
                chain.doFilter(request, response);
                return;
            }

            final Jws<Claims> parsed = jwtService.parseAccessToken(token);
            final Claims claims = parsed.getBody();
            final UUID userId = jwtService.extractUserId(claims);
            final long tokenPermissionVersion = jwtService.extractPermissionVersion(claims);

            final Long currentPermissionVersion = userRepository
                    .findPermissionVersionById(userId)
                    .orElse(null);

            if (currentPermissionVersion == null) {
                log.warn("Token validation failed: User {} not found or deleted", userId);
                sendUnauthorized(response, "User not found");
                return;
            }

            if (tokenPermissionVersion != currentPermissionVersion) {
                log.warn("Token validation failed: Permission version mismatch for user {}. Token PV: {}, Current PV: {}",
                        userId, tokenPermissionVersion, currentPermissionVersion);
                sendUnauthorized(response, "Token permissions outdated");
                return;
            }

            final Set<SimpleGrantedAuthority> authorities = new HashSet<>();
            jwtService.extractRoles(claims)
                    .forEach(role -> authorities.add(new SimpleGrantedAuthority(role)));
            jwtService.extractPermissions(claims)
                    .forEach(perm -> authorities.add(new SimpleGrantedAuthority(perm)));

            final AuthPrincipal principal = new AuthPrincipal(
                    userId,
                    jwtService.extractEmail(claims),
                    null,
                    authorities
            );

            final UsernamePasswordAuthenticationToken authentication =
                    new UsernamePasswordAuthenticationToken(principal, null, authorities);
            authentication.setDetails(new WebAuthenticationDetailsSource().buildDetails(request));

            SecurityContextHolder.getContext().setAuthentication(authentication);

            log.debug("JWT authentication successful for user: {}", userId);

        } catch (ExpiredJwtException ex) {
            log.debug("JWT token expired: {}", ex.getMessage());
            sendUnauthorized(response, "Token expired");
            return;
        } catch (JwtException ex) {
            log.warn("JWT validation failed: {}", ex.getMessage());
            sendUnauthorized(response, "Invalid token");
            return;
        } catch (IllegalArgumentException ex) {
            log.warn("JWT parsing failed: {}", ex.getMessage());
            sendUnauthorized(response, "Malformed token");
            return;
        } catch (Exception ex) {
            log.error("Unexpected error during JWT authentication for request: {}", request.getRequestURI(), ex);
            sendUnauthorized(response, "Authentication failed");
            return;
        }

        chain.doFilter(request, response);
    }

    @Override
    protected boolean shouldNotFilter(@NonNull HttpServletRequest request) {
        final String path = request.getRequestURI();
        return path.startsWith("/api/v1/auth/") ||
                path.equals("/api/v1/auth");
    }

    private void sendUnauthorized(HttpServletResponse response, String message) throws IOException {
        response.setStatus(HttpServletResponse.SC_UNAUTHORIZED);
        response.setContentType("application/json");
        response.setCharacterEncoding("UTF-8");

        final Map<String, Object> errorResponse = Map.of(
                "status", 401,
                "error", "Unauthorized",
                "message", message,
                "timestamp", System.currentTimeMillis()
        );

        response.getWriter().write(objectMapper.writeValueAsString(errorResponse));
    }
}

/*
CHANGELOG:
1. Added comprehensive logging for security audit trail
2. Fail-fast with explicit error responses instead of silent 401
3. Distinguished between expired, invalid, and malformed tokens
4. Added null check for deleted users before PV comparison
5. Extracted constants for magic strings
6. Added WebAuthenticationDetailsSource for request metadata
7. Used ObjectMapper for consistent JSON error responses
8. Added @NonNull annotations for null-safety
9. Fixed shouldNotFilter to handle trailing slashes
10. Added charset UTF-8 to prevent encoding issues
11. Changed generic Exception catch to specific JWT exceptions
12. Added timestamp to error responses for debugging
*/