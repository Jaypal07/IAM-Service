package com.jaypal.authapp.domain.infrastructure.ratelimit;

public interface RateLimitAdminService {

    void resetLoginIp(String ip);

    void resetLoginEmail(String email);

    void resetAllIpLimits(String ip);
}
