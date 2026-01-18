package com.jaypal.authapp.domain.infrastructure.ratelimit;

import jakarta.servlet.http.HttpServletRequest;
import lombok.extern.slf4j.Slf4j;

import java.net.InetAddress;
import java.net.UnknownHostException;

@Slf4j
public final class RequestIpResolver {

    // Headers only trusted when coming from known proxies
    private static final String HEADER_X_FORWARDED_FOR = "X-Forwarded-For";
    private static final String HEADER_X_REAL_IP = "X-Real-IP";

    private RequestIpResolver() {}

    public static String resolve(HttpServletRequest request) {
        if (request == null) {
            throw new IllegalStateException("HTTP request is null");
        }

        // Step 1: Try forwarded headers
        String candidate = extractFromHeaders(request);

        // Step 2: Fallback to socket IP
        if (candidate == null) {
            candidate = request.getRemoteAddr();
        }

        // Step 3: Validate
        if (!isValidIp(candidate)) {
            log.warn("Invalid client IP detected | raw={}", candidate);
            throw new IllegalStateException("Invalid client IP");
        }

        return candidate;
    }

    private static String extractFromHeaders(HttpServletRequest request) {
        String xff = request.getHeader(HEADER_X_FORWARDED_FOR);
        if (xff != null && !xff.isBlank()) {
            return xff.split(",")[0].trim();
        }

        String realIp = request.getHeader(HEADER_X_REAL_IP);
        if (realIp != null && !realIp.isBlank()) {
            return realIp.trim();
        }

        return null;
    }

    private static boolean isValidIp(String ip) {
        try {
            InetAddress.getByName(ip);
            return true;
        } catch (UnknownHostException ex) {
            return false;
        }
    }
}
