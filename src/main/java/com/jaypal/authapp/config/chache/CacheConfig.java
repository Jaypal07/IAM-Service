package com.jaypal.authapp.config.chache;

import com.github.benmanes.caffeine.cache.Caffeine;
import lombok.extern.slf4j.Slf4j;
import org.springframework.cache.CacheManager;
import org.springframework.cache.annotation.EnableCaching;
import org.springframework.cache.caffeine.CaffeineCacheManager;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

import java.util.concurrent.TimeUnit;

@Slf4j
@Configuration
@EnableCaching
public class CacheConfig {

    @Bean
    public CacheManager cacheManager() {
        final CaffeineCacheManager cacheManager = new CaffeineCacheManager("userPermissions");

        cacheManager.setCaffeine(Caffeine.newBuilder()
                .maximumSize(10_000)
                .expireAfterWrite(15, TimeUnit.MINUTES)
                .recordStats()
        );

        log.info("Cache manager initialized - TTL: 15 minutes, Max size: 10,000");

        return cacheManager;
    }
}

/*
CRITICAL: Add this dependency to pom.xml:

<dependency>
    <groupId>com.github.ben-manes.caffeine</groupId>
    <artifactId>caffeine</artifactId>
</dependency>

<dependency>
    <groupId>org.springframework.boot</groupId>
    <artifactId>spring-boot-starter-cache</artifactId>
</dependency>

CHANGELOG:
1. Created cache configuration for permission resolution
2. Used Caffeine for high-performance in-memory caching
3. Set 15-minute TTL to balance freshness and performance
4. Set max 10,000 entries to prevent memory exhaustion
5. Enabled stats recording for monitoring
6. Cache is automatically evicted on role/permission changes
*/