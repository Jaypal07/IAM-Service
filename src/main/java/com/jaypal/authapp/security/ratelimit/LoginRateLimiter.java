package com.jaypal.authapp.security.ratelimit;

import org.springframework.stereotype.Component;

import java.time.Instant;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

@Component
public class LoginRateLimiter {

    private static final int MAX_ATTEMPTS_EMAIL = 5;
    private static final int MAX_ATTEMPTS_IP = 20;
    private static final long WINDOW_SECONDS = 600; // 10 minutes

    private final Map<String, Attempt> emailAttempts = new ConcurrentHashMap<>();
    private final Map<String, Attempt> ipAttempts = new ConcurrentHashMap<>();

    public void checkRateLimit(String email, String ip) {
        check(emailAttempts, "EMAIL:" + email.toLowerCase(), MAX_ATTEMPTS_EMAIL);
        check(ipAttempts, "IP:" + ip, MAX_ATTEMPTS_IP);
    }

    public void recordSuccess(String email, String ip) {
        emailAttempts.remove("EMAIL:" + email.toLowerCase());
        ipAttempts.remove("IP:" + ip);
    }

    private void check(Map<String, Attempt> store, String key, int maxAttempts) {
        Attempt attempt = store.compute(key, (k, existing) -> {
            long now = Instant.now().getEpochSecond();

            if (existing == null || now - existing.firstAttempt > WINDOW_SECONDS) {
                return new Attempt(1, now);
            }

            if (existing.count >= maxAttempts) {
                return existing;
            }

            existing.count++;
            return existing;
        });

        if (attempt.count > maxAttempts) {
            throw new RateLimitExceededException();
        }
    }

    private static class Attempt {
        int count;
        long firstAttempt;

        Attempt(int count, long firstAttempt) {
            this.count = count;
            this.firstAttempt = firstAttempt;
        }
    }
}
