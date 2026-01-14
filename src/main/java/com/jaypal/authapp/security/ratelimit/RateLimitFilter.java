package com.jaypal.authapp.security.ratelimit;

import com.jaypal.authapp.config.JsonUtils;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.HttpStatus;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;
import java.net.URI;
import java.time.Instant;
import java.util.HashMap;
import java.util.Map;
import java.util.UUID;

@Slf4j
@Component
@RequiredArgsConstructor
public class RateLimitFilter extends OncePerRequestFilter {

    private final InMemoryRateLimiter rateLimiter;
    private static final String CORRELATION_HEADER = "X-Correlation-Id";
    private static final String TYPE_ABOUT_BLANK = "about:blank";

    @Override
    protected void doFilterInternal(
            HttpServletRequest request,
            HttpServletResponse response,
            FilterChain filterChain
    ) throws ServletException, IOException {

        String path = request.getRequestURI();
        String ip = resolveClientIp(request);

        int limit = RateLimitPolicy.limitFor(path);
        long windowSeconds = RateLimitPolicy.WINDOW.toSeconds();
        String key = path + ":" + ip;

        if (!rateLimiter.allow(key, limit, windowSeconds)) {
            String correlationId = resolveCorrelationId(request);

            log.warn("Rate limit exceeded | path={} | ip={} | correlationId={}", path, ip, correlationId);

            Map<String, Object> body = new HashMap<>();
            body.put("type", URI.create(TYPE_ABOUT_BLANK));
            body.put("title", "Too many requests");
            body.put("status", HttpStatus.TOO_MANY_REQUESTS.value());
            body.put("detail", "Too many requests. Please try again later.");
            body.put("instance", path);
            body.put("correlationId", correlationId);
            body.put("timestamp", Instant.now().toString());

            response.setStatus(HttpStatus.TOO_MANY_REQUESTS.value());
            response.setContentType("application/json");
            response.setHeader(CORRELATION_HEADER, correlationId);
            response.getWriter().write(JsonUtils.toJson(body)); // helper for converting map to JSON
            return; // stop filter chain
        }

        filterChain.doFilter(request, response);
    }

    private String resolveClientIp(HttpServletRequest request) {
        String forwarded = request.getHeader("X-Forwarded-For");
        if (forwarded != null && !forwarded.isBlank()) {
            return forwarded.split(",")[0];
        }
        return request.getRemoteAddr();
    }

    private String resolveCorrelationId(HttpServletRequest request) {
        String existing = request.getHeader(CORRELATION_HEADER);
        if (existing != null && !existing.isBlank()) {
            return existing;
        }
        return UUID.randomUUID().toString();
    }
}
