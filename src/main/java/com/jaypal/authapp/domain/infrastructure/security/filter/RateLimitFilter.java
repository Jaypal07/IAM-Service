package com.jaypal.authapp.domain.infrastructure.security.filter;

import com.jaypal.authapp.config.utils.JsonUtils;
import com.jaypal.authapp.config.properties.RateLimitProperties;
import com.jaypal.authapp.domain.infrastructure.ratelimit.CidrMatcher;
import com.jaypal.authapp.domain.infrastructure.ratelimit.RateLimitContext;
import com.jaypal.authapp.domain.infrastructure.ratelimit.RedisRateLimiter;
import com.jaypal.authapp.domain.infrastructure.ratelimit.RequestIpResolver;
import io.micrometer.core.instrument.Counter;
import io.micrometer.core.instrument.MeterRegistry;
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
import java.time.Instant;
import java.util.Map;

@Slf4j
@Component
@RequiredArgsConstructor
public class RateLimitFilter extends OncePerRequestFilter {

    private final RedisRateLimiter rateLimiter;
    private final RateLimitProperties properties;
    private final MeterRegistry meterRegistry;

    @Override
    protected void doFilterInternal(
            HttpServletRequest request,
            HttpServletResponse response,
            FilterChain chain
    ) throws ServletException, IOException {

        String path = normalize(request.getRequestURI());
        String method = request.getMethod();
        String ip = RequestIpResolver.resolve(request);

        // Hard bypass
        if (path.startsWith("/actuator") || "/api/v1/auth/login".equals(path)) {
            chain.doFilter(request, response);
            return;
        }

        if (CidrMatcher.matches(ip, properties.getInternalCidrs())) {

            Counter.builder("auth.ratelimit.internal.bypass")
                    .description("Requests bypassing rate limiting due to internal CIDR")
                    .tag("endpoint", path)
                    .tag("method", method)
                    .register(meterRegistry)
                    .increment();

            log.debug(
                    "Internal traffic detected. Rate limit bypassed | ip={} path={}",
                    ip,
                    path
            );
            chain.doFilter(request, response);
            return;
        }

        RateLimitProperties.Limit limit =
                properties.getEndpoints().getOrDefault(
                        path,
                        properties.getEndpoints().get("default")
                );

        String key = "rl:ip:" + ip + ":" + path;

        RateLimitContext ctx = new RateLimitContext(path, method, "ip");

        boolean allowed = rateLimiter.allow(
                key,
                limit.getCapacity(),
                limit.getRefillPerSecond(),
                ctx
        );

        if (!allowed) {
            response.setStatus(HttpStatus.TOO_MANY_REQUESTS.value());
            response.setContentType("application/json");
            response.getWriter().write(JsonUtils.toJson(Map.of(
                    "status", 429,
                    "error", "Too many requests",
                    "timestamp", Instant.now().toString()
            )));
            return;
        }

        chain.doFilter(request, response);
    }

    private String normalize(String path) {
        if (path.endsWith("/") && path.length() > 1) {
            return path.substring(0, path.length() - 1);
        }
        return path;
    }
}
