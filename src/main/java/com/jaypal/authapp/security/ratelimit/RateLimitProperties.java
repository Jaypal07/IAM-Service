package com.jaypal.authapp.security.ratelimit;

import lombok.Data;
import org.springframework.boot.context.properties.ConfigurationProperties;

import java.util.ArrayList;
import java.util.List;
import java.util.Map;

@Data
@ConfigurationProperties(prefix = "rate-limit")
public class RateLimitProperties {


    private List<String> internalCidrs = new ArrayList<>();
    private Map<String, Limit> endpoints;
    private Limit loginEmail;
    private Limit loginIp;
    private Limit invalidRefresh;
    private Limit refreshRotate;

    @Data
    public static class Limit {
        private int capacity;
        private int refillPerSecond;
    }
}
