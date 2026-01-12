package com.jaypal.authapp.auth.api;

import com.jaypal.authapp.audit.annotation.AuthAudit;
import com.jaypal.authapp.audit.domain.AuthAuditEvent;
import com.jaypal.authapp.audit.domain.AuthProvider;
import com.jaypal.authapp.audit.domain.AuditSubjectType;
import com.jaypal.authapp.auth.application.TokenIntrospectionService;
import com.jaypal.authapp.auth.dto.TokenIntrospectionResponse;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestHeader;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@Slf4j
@RestController
@RequestMapping("/api/v1/auth")
@RequiredArgsConstructor
public class TokenIntrospectionController {

    private final TokenIntrospectionService introspectionService;

    @AuthAudit(
            event = AuthAuditEvent.TOKEN_INTROSPECTED,
            subject = AuditSubjectType.ANONYMOUS,
            provider = AuthProvider.SYSTEM
    )
    @PostMapping("/introspect")
    public TokenIntrospectionResponse introspect(
            @RequestHeader(name = "Authorization", required = false) String header
    ) {
        if (header == null || !header.startsWith("Bearer ")) {
            log.debug("Token introspection called without bearer token");
            return TokenIntrospectionResponse.inactive();
        }

        return introspectionService.introspect(header.substring(7).trim());
    }
}
