package com.jaypal.authapp.security.ratelimit;

public interface RateLimitAdminService {

    void resetLoginIp(String ip);

    void resetLoginEmail(String email);

    void resetAllIpLimits(String ip);
}
