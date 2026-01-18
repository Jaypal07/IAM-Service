package com.jaypal.authapp.api.auth;

import com.jaypal.authapp.common.annotation.AuthAudit;
import com.jaypal.authapp.domain.audit.entity.AuthAuditEvent;
import com.jaypal.authapp.domain.audit.entity.AuthProvider;
import com.jaypal.authapp.domain.audit.entity.AuditSubjectType;
import com.jaypal.authapp.service.auth.TokenIntrospectionService;
import com.jaypal.authapp.dto.auth.TokenIntrospectionResponse;
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
            event = AuthAuditEvent.TOKEN_INTROSPECTION_SUCCESS,
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
