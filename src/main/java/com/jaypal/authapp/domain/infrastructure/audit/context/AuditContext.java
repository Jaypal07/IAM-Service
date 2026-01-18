package com.jaypal.authapp.domain.infrastructure.audit.context;

import com.jaypal.authapp.domain.dto.audit.AuditRequestContext;
import jakarta.servlet.http.HttpServletRequest;

public final class AuditContext {

    private static final String X_FORWARDED_FOR = "X-Forwarded-For";
    private static final String X_REAL_IP = "X-Real-IP";
    private static final String USER_AGENT = "User-Agent";
    private static final String UNKNOWN = "unknown";

    private AuditContext() {
        throw new UnsupportedOperationException("Utility class");
    }

    public static AuditRequestContext fromRequest(HttpServletRequest request) {
        if (request == null) {
            return null;
        }

        final String ipAddress = extractIpAddress(request);
        final String userAgent = extractUserAgent(request);

        return new AuditRequestContext(ipAddress, userAgent, null);
    }

    public static AuditRequestContext fromThreadLocal() {
        return AuditContextHolder.getContext();
    }

    private static String extractIpAddress(HttpServletRequest request) {
        String ip = request.getHeader(X_FORWARDED_FOR);

        if (ip != null && !ip.isBlank() && !UNKNOWN.equalsIgnoreCase(ip)) {
            final int commaIndex = ip.indexOf(',');
            return commaIndex > 0 ? ip.substring(0, commaIndex).trim() : ip.trim();
        }

        ip = request.getHeader(X_REAL_IP);
        if (ip != null && !ip.isBlank() && !UNKNOWN.equalsIgnoreCase(ip)) {
            return ip.trim();
        }

        ip = request.getRemoteAddr();
        return ip != null ? ip : UNKNOWN;
    }

    private static String extractUserAgent(HttpServletRequest request) {
        final String userAgent = request.getHeader(USER_AGENT);

        if (userAgent == null || userAgent.isBlank()) {
            return UNKNOWN;
        }

        return userAgent.length() > 512 ? userAgent.substring(0, 512) : userAgent;
    }
}
