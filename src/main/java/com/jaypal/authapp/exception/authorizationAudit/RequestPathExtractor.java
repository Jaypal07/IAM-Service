package com.jaypal.authapp.exception.authorizationAudit;

import org.springframework.stereotype.Component;
import org.springframework.web.context.request.ServletWebRequest;
import org.springframework.web.context.request.WebRequest;

/**
 * Extracts request path from web requests.
 * Follows Single Responsibility Principle and DRY.
 */
@Component
public class RequestPathExtractor {

    private static final String NOT_AVAILABLE = "N/A";

    public String extract(WebRequest request) {
        if (request instanceof ServletWebRequest servletWebRequest) {
            return servletWebRequest.getRequest().getRequestURI();
        }
        return NOT_AVAILABLE;
    }
}