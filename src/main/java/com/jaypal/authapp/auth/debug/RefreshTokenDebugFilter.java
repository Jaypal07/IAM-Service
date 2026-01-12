package com.jaypal.authapp.auth.debug;

import com.jaypal.authapp.auth.infrastructure.RefreshTokenExtractor;
import com.jaypal.authapp.token.application.RefreshTokenHasher;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.context.annotation.Profile;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;

@Slf4j
@Profile("debug")
@RequiredArgsConstructor
public class RefreshTokenDebugFilter extends OncePerRequestFilter {

    private final RefreshTokenExtractor extractor;
    private final RefreshTokenHasher hasher;

    @Override
    protected boolean shouldNotFilter(HttpServletRequest request) {
        return !request.getRequestURI().equals("/api/v1/auth/refresh");
    }

    @Override
    protected void doFilterInternal(
            HttpServletRequest request,
            HttpServletResponse response,
            FilterChain chain
    ) throws ServletException, IOException {

        extractor.extract(request).ifPresent(token -> {
            try {
                String hash = hasher.hash(token);
                log.debug(
                        "REFRESH DEBUG → source={}, hash={}",
                        resolveSource(request),
                        hash.substring(0, 12)
                );
            } catch (Exception ex) {
                log.debug("REFRESH DEBUG → token hash failed");
            }
        });

        chain.doFilter(request, response);
    }

    private String resolveSource(HttpServletRequest request) {
        if (request.getHeader("X-Refresh-Token") != null) {
            return "X-Refresh-Token";
        }
        if (request.getCookies() != null) {
            return "COOKIE";
        }
        return "UNKNOWN";
    }
}
