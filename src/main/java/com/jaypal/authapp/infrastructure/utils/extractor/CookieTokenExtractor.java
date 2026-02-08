package com.jaypal.authapp.infrastructure.utils.extractor;

import com.jaypal.authapp.infrastructure.utils.CookieService;
import jakarta.servlet.http.Cookie;
import jakarta.servlet.http.HttpServletRequest;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Component;

import java.util.Arrays;
import java.util.Objects;
import java.util.Optional;

@Slf4j
@Component
@RequiredArgsConstructor
public class CookieTokenExtractor {

    private final CookieService cookieService;

    public Optional<String> extract(HttpServletRequest request) {
        Cookie[] cookies = request.getCookies();
        
        if (cookies == null) {
            log.warn("No cookies present in request | uri={} origin={}", 
                request.getRequestURI(), 
                request.getHeader("Origin"));
            return Optional.empty();
        }
        
        log.debug("Cookies received | count={} names={}", 
            cookies.length,
            Arrays.stream(cookies).map(Cookie::getName).collect(java.util.stream.Collectors.joining(", ")));
        
        Optional<String> result = Arrays.stream(cookies)
                .filter(Objects::nonNull)
                .filter(c -> cookieService.getRefreshTokenCookieName().equals(c.getName()))
                .map(Cookie::getValue)
                .filter(this::isValid)
                .findFirst();
        
        if (result.isEmpty()) {
            log.warn("Refresh token cookie not found | expected={} available={}", 
                cookieService.getRefreshTokenCookieName(),
                Arrays.stream(cookies).map(Cookie::getName).collect(java.util.stream.Collectors.joining(", ")));
        }
        
        return result;
    }

    private boolean isValid(String value) {
        boolean valid = value != null && !value.isBlank();
        if (!valid) {
            log.debug("Refresh token cookie present but empty");
        }
        return valid;
    }
}
