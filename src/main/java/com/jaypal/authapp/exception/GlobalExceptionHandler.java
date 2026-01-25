package com.jaypal.authapp.exception;

import com.jaypal.authapp.domain.token.exception.*;
import com.jaypal.authapp.domain.user.exception.*;
import com.jaypal.authapp.exception.auth.*;
import com.jaypal.authapp.exception.authorizationAudit.AuditLogger;
import com.jaypal.authapp.exception.handler.*;
import com.jaypal.authapp.exception.response.ApiErrorResponseBuilder;
import com.jaypal.authapp.infrastructure.ratelimit.RateLimitExceededException;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.dao.DataIntegrityViolationException;
import org.springframework.http.ResponseEntity;
import org.springframework.http.converter.HttpMessageNotReadableException;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.InternalAuthenticationServiceException;
import org.springframework.security.authentication.LockedException;
import org.springframework.web.HttpRequestMethodNotSupportedException;
import org.springframework.web.bind.MethodArgumentNotValidException;
import org.springframework.web.bind.MissingServletRequestParameterException;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.RestControllerAdvice;
import org.springframework.web.context.request.WebRequest;
import org.springframework.web.method.annotation.HandlerMethodValidationException;
import org.springframework.web.method.annotation.MethodArgumentTypeMismatchException;
import org.springframework.web.servlet.resource.NoResourceFoundException;

import java.util.Map;

/**
 * Refactored GlobalExceptionHandler following SOLID principles.
 * Delegates exception handling to specialized handler components.
 */
@Slf4j
@RestControllerAdvice
@RequiredArgsConstructor
public class GlobalExceptionHandler {

    private final AuditLogger auditLogger;
    private final ApiErrorResponseBuilder problemBuilder;

    // Specialized handlers
    private final AuthorizationExceptionHandler authorizationHandler;
    private final AuthenticationExceptionHandler authenticationHandler;
    private final EmailVerificationExceptionHandler emailVerificationHandler;
    private final PasswordTokenExceptionHandler passwordTokenHandler;
    private final UserDomainExceptionHandler userDomainHandler;
    private final ValidationExceptionHandler validationHandler;
    private final InfrastructureExceptionHandler infrastructureHandler;

    /* =====================
       AUTHORIZATION
       ===================== */

    @ExceptionHandler({
            org.springframework.security.access.AccessDeniedException.class,
            org.springframework.security.authorization.AuthorizationDeniedException.class
    })
    public ResponseEntity<Map<String, Object>> handleAccessDenied(
            Exception ex,
            WebRequest request
    ) {
        return authorizationHandler.handleAccessDenied(ex, request, auditLogger);
    }

    /* =====================
       AUTHENTICATION
       ===================== */

    @ExceptionHandler(BadCredentialsException.class)
    public ResponseEntity<Map<String, Object>> handleBadCredentials(
            BadCredentialsException ex,
            WebRequest request
    ) {
        return authenticationHandler.handleBadCredentials(ex, request);
    }

    @ExceptionHandler(AuthenticatedUserMissingException.class)
    public ResponseEntity<Map<String, Object>> handleAuthenticatedUserMissing(
            AuthenticatedUserMissingException ex,
            WebRequest request
    ) {
        return authenticationHandler.handleAuthenticatedUserMissing(ex, request);
    }

    @ExceptionHandler(UserAccountDisabledException.class)
    public ResponseEntity<Map<String, Object>> handleAccountDisabled(
            UserAccountDisabledException ex,
            WebRequest request
    ) {
        return authenticationHandler.handleAccountDisabled(ex, request);
    }

    @ExceptionHandler(UserAlreadyDisable.class)
    public ResponseEntity<Map<String, Object>> handleUserAlreadyDisable(
            UserAlreadyDisable ex,
            WebRequest request
    ){
        return authenticationHandler.handleUserAlreadyDisable(ex, request);
    }

    @ExceptionHandler(EmailNotVerifiedException.class)
    public ResponseEntity<Map<String, Object>> handleEmailNotVerified(
            EmailNotVerifiedException ex,
            WebRequest request
    ) {
        return authenticationHandler.handleEmailNotVerified(ex, request);
    }

    @ExceptionHandler(LockedException.class)
    public ResponseEntity<Map<String, Object>> handleAccountLocked(
            LockedException ex,
            WebRequest request
    ) {
        return authenticationHandler.handleAccountLocked(ex, request);
    }

    @ExceptionHandler(InternalAuthenticationServiceException.class)
    public ResponseEntity<Map<String, Object>> handleInternalAuthenticationServiceException(
            InternalAuthenticationServiceException ex,
            WebRequest request
    ) {
        return authenticationHandler.handleInternalAuthenticationServiceException(ex, request);
    }

    /* =====================
       EMAIL VERIFICATION
       ===================== */

    @ExceptionHandler(EmailAlreadyExistsException.class)
    public ResponseEntity<Map<String, Object>> handleEmailAlreadyExists(
            EmailAlreadyExistsException ex,
            WebRequest request
    ) {
        return emailVerificationHandler.handleEmailAlreadyExists(ex, request);
    }

    @ExceptionHandler(EmailAlreadyVerifiedException.class)
    public ResponseEntity<Map<String, Object>> handleAlreadyVerified(
            EmailAlreadyVerifiedException ex,
            WebRequest request
    ) {
        return emailVerificationHandler.handleEmailAlreadyVerified(ex, request);
    }

    @ExceptionHandler({
            VerificationTokenExpiredException.class,
            VerificationTokenInvalidException.class
    })
    public ResponseEntity<Map<String, Object>> handleVerificationTokenFailures(
            RuntimeException ex,
            WebRequest request
    ) {
        return emailVerificationHandler.handleVerificationTokenFailures(ex, request);
    }

    @ExceptionHandler(EmailNotRegisteredException.class)
    public ResponseEntity<Void> swallowEmailNotRegistered() {
        return emailVerificationHandler.handleEmailNotRegistered();
    }

    @ExceptionHandler(SilentEmailVerificationResendException.class)
    public ResponseEntity<Void> handleSilentVerificationResend(
            SilentEmailVerificationResendException ex,
            WebRequest request
    ) {
        return emailVerificationHandler.handleSilentVerificationResend(ex, request);
    }

    @ExceptionHandler(EmailDeliveryFailedException.class)
    public ResponseEntity<Map<String, Object>> handleEmailDeliveryFailed(
            EmailDeliveryFailedException ex,
            WebRequest request
    ) {
        return emailVerificationHandler.handleEmailDeliveryFailed(ex, request);
    }

    /* =====================
       PASSWORD & TOKENS
       ===================== */

    @ExceptionHandler({
            PasswordPolicyViolationException.class,
            PasswordResetTokenInvalidException.class,
            PasswordResetTokenExpiredException.class
    })
    public ResponseEntity<Map<String, Object>> handlePasswordFailures(
            RuntimeException ex,
            WebRequest request
    ) {
        return passwordTokenHandler.handlePasswordFailures(ex, request);
    }

    @ExceptionHandler({
            RefreshTokenExpiredException.class,
            RefreshTokenNotFoundException.class,
            RefreshTokenRevokedException.class,
            RefreshTokenUserMismatchException.class,
            RefreshTokenException.class,
            InvalidRefreshTokenException.class,
            MissingRefreshTokenException.class
    })
    public ResponseEntity<Map<String, Object>> handleRefreshTokenFailures(
            RuntimeException ex,
            WebRequest request
    ) {
        return passwordTokenHandler.handleRefreshTokenFailures(ex, request);
    }

    /* =====================
       USER DOMAIN
       ===================== */

    @ExceptionHandler(InvalidRoleOperationException.class)
    public ResponseEntity<Map<String, Object>> handleInvalidRoleOperation(
            InvalidRoleOperationException ex,
            WebRequest request
    ) {
        return userDomainHandler.handleInvalidRoleOperation(ex, request);
    }

    @ExceptionHandler(ResourceNotFoundException.class)
    public ResponseEntity<Map<String, Object>> handleResourceNotFound(
            com.jaypal.authapp.domain.user.exception.ResourceNotFoundException ex,
            WebRequest request
    ) {
        return userDomainHandler.handleResourceNotFound(ex, request);
    }

    /* =====================
       VALIDATION
       ===================== */

    @ExceptionHandler(MethodArgumentNotValidException.class)
    public ResponseEntity<Map<String, Object>> handleValidation(
            MethodArgumentNotValidException ex,
            WebRequest request
    ) {
        return validationHandler.handleMethodArgumentNotValid(ex, request);
    }

    @ExceptionHandler(HandlerMethodValidationException.class)
    public ResponseEntity<Map<String, Object>> handleHandlerMethodValidation(
            HandlerMethodValidationException ex,
            WebRequest request
    ) {
        return validationHandler.handleHandlerMethodValidation(ex, request);
    }

    @ExceptionHandler(jakarta.validation.ConstraintViolationException.class)
    public ResponseEntity<Map<String, Object>> handleConstraintViolation(
            jakarta.validation.ConstraintViolationException ex,
            WebRequest request
    ) {
        return validationHandler.handleConstraintViolation(ex, request);
    }

    @ExceptionHandler(MethodArgumentTypeMismatchException.class)
    public ResponseEntity<Map<String, Object>> handleMethodArgumentTypeMismatch(
            MethodArgumentTypeMismatchException ex,
            WebRequest request
    ) {
        return validationHandler.handleMethodArgumentTypeMismatch(ex, request);
    }

    /* =====================
       INFRASTRUCTURE
       ===================== */

    @ExceptionHandler(DataIntegrityViolationException.class)
    public ResponseEntity<Map<String, Object>> handleDataIntegrity(
            DataIntegrityViolationException ex,
            WebRequest request
    ) {
        return infrastructureHandler.handleDataIntegrity(ex, request);
    }

    @ExceptionHandler(RateLimitExceededException.class)
    public ResponseEntity<Map<String, Object>> handleRateLimit(
            RateLimitExceededException ex,
            WebRequest request
    ) {
        return infrastructureHandler.handleRateLimit(ex, request);
    }

    @ExceptionHandler(NoResourceFoundException.class)
    public ResponseEntity<Map<String, Object>> handleNoResource(
            NoResourceFoundException ex,
            WebRequest request
    ) {
        return infrastructureHandler.handleNoResource(ex, request);
    }

    @ExceptionHandler(HttpMessageNotReadableException.class)
    public ResponseEntity<Map<String, Object>> handleNotReadable(
            HttpMessageNotReadableException ex,
            WebRequest request
    ) {
        return infrastructureHandler.handleHttpMessageNotReadable(ex, request);
    }

    @ExceptionHandler(MissingServletRequestParameterException.class)
    public ResponseEntity<Map<String, Object>> handleMissingRequestParam(
            MissingServletRequestParameterException ex,
            WebRequest request
    ) {
        return infrastructureHandler.handleMissingRequestParameter(ex, request);
    }

    @ExceptionHandler(IllegalArgumentException.class)
    public ResponseEntity<Map<String, Object>> handleIllegalArgument(
            IllegalArgumentException ex,
            WebRequest request
    ) {
        return infrastructureHandler.handleIllegalArgument(ex, request);
    }

    @ExceptionHandler(HttpRequestMethodNotSupportedException.class)
    public ResponseEntity<org.springframework.http.ProblemDetail> handleMethodNotSupported(
            HttpRequestMethodNotSupportedException ex,
            WebRequest request
    ) {
        return infrastructureHandler.handleMethodNotSupported(ex, request);
    }

    @ExceptionHandler(Exception.class)
    public ResponseEntity<Map<String, Object>> handleGeneric(
            Exception ex,
            WebRequest request
    ) {
        return infrastructureHandler.handleGenericException(ex, request);
    }
}