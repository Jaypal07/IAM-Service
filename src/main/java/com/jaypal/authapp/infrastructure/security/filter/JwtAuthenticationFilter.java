package com.jaypal.authapp.infrastructure.security.filter;

import com.jaypal.authapp.domain.user.repository.UserRepository;
import com.jaypal.authapp.exception.response.ApiErrorResponseBuilder;
import com.jaypal.authapp.infrastructure.principal.AuthPrincipal;
import com.jaypal.authapp.infrastructure.security.jwt.JwtService;
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
import org.springframework.http.HttpStatus;
import org.springframework.lang.NonNull;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.web.authentication.WebAuthenticationDetailsSource;
import org.springframework.stereotype.Component;
import org.springframework.web.context.request.ServletWebRequest;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;
import java.util.*;

@Slf4j
@Component
@RequiredArgsConstructor
public class JwtAuthenticationFilter extends OncePerRequestFilter {

    private static final String AUTH_HEADER = "Authorization";
    private static final String BEARER_PREFIX = "Bearer ";
    private static final int BEARER_PREFIX_LENGTH = 7;

    private final JwtService jwtService;
    private final UserRepository userRepository;
    private final ApiErrorResponseBuilder errorResponseBuilder;

    @Override
    protected void doFilterInternal(
            @NonNull HttpServletRequest request,
            @NonNull HttpServletResponse response,
            @NonNull FilterChain chain
    ) throws ServletException, IOException {

        Optional<String> tokenOpt = extractBearerToken(request);

        if (tokenOpt.isEmpty()) {
            chain.doFilter(request, response);
            return;
        }

        try {
            authenticate(tokenOpt.get(), request);

            log.debug(
                    "JWT authentication successful for user: {}",
                    ((AuthPrincipal) SecurityContextHolder.getContext()
                            .getAuthentication()
                            .getPrincipal())
                            .getUserId()
            );

        } catch (ExpiredJwtException ex) {
            log.debug("JWT token expired: {}", ex.getMessage());
            writeUnauthorized(response, request, ex, "Token expired");
            return;

        } catch (JwtException ex) {
            log.warn("JWT validation failed: {}", ex.getMessage());
            writeUnauthorized(response, request, ex, "Invalid token");
            return;

        } catch (IllegalArgumentException ex) {
            log.warn("JWT parsing failed: {}", ex.getMessage());
            writeUnauthorized(response, request, ex, "Malformed token");
            return;

        } catch (Exception ex) {
            log.error(
                    "Unexpected error during JWT authentication for request: {}",
                    request.getRequestURI(),
                    ex
            );
            writeUnauthorized(response, request, ex, "Authentication failed");
            return;
        }

        chain.doFilter(request, response);
    }

    private Optional<String> extractBearerToken(HttpServletRequest request) {
        String header = request.getHeader(AUTH_HEADER);

        if (header == null || !header.startsWith(BEARER_PREFIX)) {
            return Optional.empty();
        }

        String token = header.substring(BEARER_PREFIX_LENGTH).trim();
        return token.isEmpty() ? Optional.empty() : Optional.of(token);
    }

    private void authenticate(String token, HttpServletRequest request) {
        Jws<Claims> parsed = jwtService.parseAccessToken(token);
        Claims claims = parsed.getBody();

        UUID userId = jwtService.extractUserId(claims);
        long tokenPermissionVersion = jwtService.extractPermissionVersion(claims);

        validatePermissionVersion(userId, tokenPermissionVersion);

        Set<SimpleGrantedAuthority> authorities = extractAuthorities(claims);
        AuthPrincipal principal = buildPrincipal(userId, claims, authorities);

        UsernamePasswordAuthenticationToken authentication =
                new UsernamePasswordAuthenticationToken(principal, null, authorities);

        authentication.setDetails(
                new WebAuthenticationDetailsSource().buildDetails(request)
        );

        SecurityContextHolder.getContext().setAuthentication(authentication);
    }

    private void validatePermissionVersion(UUID userId, long tokenPermissionVersion) {
        Long currentPermissionVersion = userRepository
                .findPermissionVersionById(userId)
                .orElse(null);

        if (currentPermissionVersion == null) {
            log.warn("Token validation failed: User {} not found or deleted", userId);
            throw new IllegalStateException("User not found");
        }

        if (!Objects.equals(tokenPermissionVersion, currentPermissionVersion)) {
            log.warn(
                    "Token validation failed: Permission version mismatch for user {}. Token PV: {}, Current PV: {}",
                    userId,
                    tokenPermissionVersion,
                    currentPermissionVersion
            );
            throw new IllegalStateException("Token permissions outdated");
        }
    }

    private Set<SimpleGrantedAuthority> extractAuthorities(Claims claims) {
        Set<SimpleGrantedAuthority> authorities = new HashSet<>();

        jwtService.extractRoles(claims)
                .forEach(role -> authorities.add(new SimpleGrantedAuthority(role)));

        jwtService.extractPermissions(claims)
                .forEach(perm -> authorities.add(new SimpleGrantedAuthority(perm)));

        return authorities;
    }

    private AuthPrincipal buildPrincipal(
            UUID userId,
            Claims claims,
            Set<SimpleGrantedAuthority> authorities
    ) {
        return new AuthPrincipal(
                userId,
                jwtService.extractEmail(claims),
                null,
                authorities
        );
    }

    @Override
    protected boolean shouldNotFilter(@NonNull HttpServletRequest request) {
        String path = request.getRequestURI();
        return path.startsWith("/api/v1/auth/") || path.equals("/api/v1/auth");
    }

    private void writeUnauthorized(
            HttpServletResponse response,
            HttpServletRequest request,
            Throwable ex,
            String defaultMessage
    ) throws IOException {

        var entity = errorResponseBuilder.build(
                HttpStatus.UNAUTHORIZED,
                "Unauthorized",
                errorResponseBuilder.resolveMessage(ex, defaultMessage),
                new ServletWebRequest(request),
                "JWT authentication failure",
                false
        );

        response.setStatus(entity.getStatusCode().value());
        response.setContentType("application/json");
        response.setCharacterEncoding("UTF-8");

        entity.getHeaders().forEach((k, v) ->
                response.addHeader(k, String.join(",", v))
        );

        response.getWriter().write(
                new com.fasterxml.jackson.databind.ObjectMapper()
                        .writeValueAsString(entity.getBody())
        );
        response.getWriter().flush();
    }
}
