package com.jaypal.authapp.security.ratelimit;

import org.springframework.stereotype.Component;

import java.time.Instant;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

@Component
public class InMemoryRateLimiter {

    private static class Bucket {
        int count;
        long windowStart;
    }

    private final Map<String, Bucket> buckets = new ConcurrentHashMap<>();

    public boolean allow(String key, int limit, long windowSeconds) {
        long now = Instant.now().getEpochSecond();

        Bucket bucket = buckets.compute(key, (k, existing) -> {
            if (existing == null || now - existing.windowStart >= windowSeconds) {
                Bucket b = new Bucket();
                b.count = 1;
                b.windowStart = now;
                return b;
            }
            existing.count++;
            return existing;
        });

        return bucket.count <= limit;
    }
}
