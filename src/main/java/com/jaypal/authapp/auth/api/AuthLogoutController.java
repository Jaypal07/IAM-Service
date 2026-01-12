package com.jaypal.authapp.auth.api;

import com.jaypal.authapp.audit.annotation.AuthAudit;
import com.jaypal.authapp.audit.domain.AuthAuditEvent;
import com.jaypal.authapp.audit.domain.AuthProvider;
import com.jaypal.authapp.audit.domain.AuditSubjectType;
import com.jaypal.authapp.auth.application.AuthService;
import com.jaypal.authapp.security.principal.AuthPrincipal;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@Slf4j
@RestController
@RequestMapping("/api/v1/auth")
@RequiredArgsConstructor
public class AuthLogoutController {

    private final AuthService authService;

    @AuthAudit(
            event = AuthAuditEvent.TOKEN_REVOKED,
            subject = AuditSubjectType.USER_ID,
            provider = AuthProvider.SYSTEM,
            subjectParam = "principal"
    )
    @PostMapping("/logout-all")
    public ResponseEntity<Void> logoutAll(
            @AuthenticationPrincipal AuthPrincipal principal
    ) {
        if (principal == null || principal.getUserId() == null) {
            log.warn("Logout-all called without authenticated principal");
            return ResponseEntity.status(401).build();
        }

        authService.logoutAllSessions(principal.getUserId());

        return ResponseEntity.noContent().build();
    }
}
