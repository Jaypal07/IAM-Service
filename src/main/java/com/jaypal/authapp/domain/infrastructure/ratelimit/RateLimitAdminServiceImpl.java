package com.jaypal.authapp.domain.infrastructure.ratelimit;

import io.micrometer.core.instrument.Counter;
import io.micrometer.core.instrument.MeterRegistry;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.data.redis.core.StringRedisTemplate;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.stereotype.Service;

import java.util.Set;

@Slf4j
@Service
@RequiredArgsConstructor
public class RateLimitAdminServiceImpl implements RateLimitAdminService {

    private final StringRedisTemplate redisTemplate;
    private final MeterRegistry meterRegistry;

    @Override
    @PreAuthorize("hasAuthority('RATE_LIMIT_RESET')")
    public void resetLoginIp(String ip) {
        String key = "rl:login:ip:" + ip;
        redisTemplate.delete(key);

        Counter.builder("auth.ratelimit.reset")
                .tag("type", "login_ip")
                .register(meterRegistry)
                .increment();

        log.warn("Admin reset login IP rate limit | ip={}", ip);
    }

    @Override
    @PreAuthorize("hasAuthority('RATE_LIMIT_RESET')")
    public void resetLoginEmail(String email) {
        String normalized = email.toLowerCase().trim();
        String key = "rl:login:email:" + normalized;
        redisTemplate.delete(key);

        Counter.builder("auth.ratelimit.reset")
                .tag("type", "login_email")
                .register(meterRegistry)
                .increment();

        log.warn("Admin reset login email rate limit | email={}", normalized);
    }

    @Override
    @PreAuthorize("hasAuthority('RATE_LIMIT_RESET')")
    public void resetAllIpLimits(String ip) {
        Set<String> keys = redisTemplate.keys("rl:ip:" + ip + ":*");

        if (!keys.isEmpty()) {
            redisTemplate.delete(keys);
        }

        Counter.builder("auth.ratelimit.reset")
                .tag("type", "all_ip")
                .register(meterRegistry)
                .increment();

        log.warn("Admin reset ALL rate limits for IP | ip={} keys={}", ip, keys.size());
    }
}
