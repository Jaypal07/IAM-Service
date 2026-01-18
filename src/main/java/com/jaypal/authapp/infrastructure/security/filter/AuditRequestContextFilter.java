package com.jaypal.authapp.infrastructure.security.filter;

import com.jaypal.authapp.infrastructure.audit.context.AuditContextHolder;
import com.jaypal.authapp.dto.audit.AuditRequestContext;
import com.jaypal.authapp.infrastructure.principal.AuthPrincipal;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.extern.slf4j.Slf4j;
import org.springframework.lang.NonNull;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;

@Slf4j
@Component
public class AuditRequestContextFilter extends OncePerRequestFilter {

    private static final String USER_AGENT = "User-Agent";
    private static final String UNKNOWN = "unknown";

    @Override
    protected void doFilterInternal(
            @NonNull HttpServletRequest request,
            @NonNull HttpServletResponse response,
            @NonNull FilterChain chain
    ) throws ServletException, IOException {

        try {
            String ipAddress = extractIpAddress(request);
            String userAgent = extractUserAgent(request);

            AuditContextHolder.setContext(
                    new AuditRequestContext(ipAddress, userAgent, null)
            );
            Authentication authentication =
                    SecurityContextHolder.getContext().getAuthentication();

            if (authentication != null
                    && authentication.isAuthenticated()
                    && authentication.getPrincipal() instanceof AuthPrincipal principal) {

                AuditRequestContext ctx = AuditContextHolder.getContext();

                AuditContextHolder.setContext(
                        new AuditRequestContext(
                                ctx.ipAddress(),
                                ctx.userAgent(),
                                principal.getUserId().toString()
                        )
                );

                log.trace("Audit userId set from SecurityContext: {}", principal.getUserId());
            }


            log.trace(
                    "Audit context initialized: ip={}, ua={}",
                    maskIp(ipAddress),
                    maskUserAgent(userAgent)
            );

            chain.doFilter(request, response);

        } finally {
            AuditContextHolder.clear();
        }
    }

    private String extractIpAddress(HttpServletRequest request) {
        // Trust container configuration. Do NOT trust spoofable headers here.
        String ip = request.getRemoteAddr();
        return ip != null ? ip : UNKNOWN;
    }

    private String extractUserAgent(HttpServletRequest request) {
        String ua = request.getHeader(USER_AGENT);
        if (ua == null || ua.isBlank()) {
            return UNKNOWN;
        }
        return ua.length() > 512 ? ua.substring(0, 512) : ua;
    }

    private String maskIp(String ip) {
        if (ip == null || UNKNOWN.equals(ip)) {
            return UNKNOWN;
        }

        if (ip.contains(":")) { // IPv6
            return "***:***";
        }

        int lastDot = ip.lastIndexOf('.');
        return lastDot > 0 ? ip.substring(0, lastDot) + ".***" : "***";
    }

    private String maskUserAgent(String ua) {
        if (ua == null || ua.length() <= 20) {
            return "***";
        }
        return ua.substring(0, 20) + "...";
    }
}
