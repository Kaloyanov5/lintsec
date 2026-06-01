package com.lintsec.exception;

import jakarta.servlet.http.HttpServletRequest;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.http.ProblemDetail;
import org.springframework.http.ResponseEntity;
import org.springframework.http.converter.HttpMessageNotReadableException;
import org.springframework.security.access.AccessDeniedException;
import org.springframework.web.bind.MethodArgumentNotValidException;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.RestControllerAdvice;

import java.net.URI;
import java.util.ArrayList;
import java.util.List;

@RestControllerAdvice
public class GlobalExceptionHandler {

    private static final Logger log = LoggerFactory.getLogger(GlobalExceptionHandler.class);

    private static final URI ERR_VALIDATION = URI.create("https://lintsec.local/errors/validation");
    private static final URI ERR_UNAUTHORIZED = URI.create("https://lintsec.local/errors/unauthorized");
    private static final URI ERR_FORBIDDEN = URI.create("https://lintsec.local/errors/forbidden");
    private static final URI ERR_NOT_FOUND = URI.create("https://lintsec.local/errors/not-found");
    private static final URI ERR_CONFLICT = URI.create("https://lintsec.local/errors/conflict");
    private static final URI ERR_RATE_LIMITED = URI.create("https://lintsec.local/errors/rate-limited");
    private static final URI ERR_INTERNAL = URI.create("https://lintsec.local/errors/internal");

    @ExceptionHandler(ApiException.class)
    public ResponseEntity<ProblemDetail> handleApi(ApiException ex, HttpServletRequest req) {
        ProblemDetail pd = ProblemDetail.forStatus(ex.status());
        pd.setTitle(titleFor(ex.status()));
        pd.setDetail(ex.getMessage());
        pd.setType(typeFor(ex.status()));
        pd.setInstance(URI.create(req.getRequestURI()));

        HttpHeaders headers = new HttpHeaders();
        headers.setContentType(MediaType.APPLICATION_PROBLEM_JSON);

        if (ex instanceof RateLimitedException rl) {
            pd.setProperty("retryAfterSeconds", rl.retryAfterSeconds());
            headers.add(HttpHeaders.RETRY_AFTER, String.valueOf(rl.retryAfterSeconds()));
        }

        return new ResponseEntity<>(pd, headers, ex.status());
    }

    @ExceptionHandler(MethodArgumentNotValidException.class)
    public ResponseEntity<ProblemDetail> handleValidation(MethodArgumentNotValidException ex, HttpServletRequest req) {
        ProblemDetail pd = ProblemDetail.forStatus(HttpStatus.BAD_REQUEST);
        pd.setTitle("Validation failed");
        pd.setDetail("one or more fields are invalid");
        pd.setType(ERR_VALIDATION);
        pd.setInstance(URI.create(req.getRequestURI()));

        List<FieldError> fieldErrors = new ArrayList<>();
        ex.getBindingResult().getFieldErrors().forEach(fe ->
                fieldErrors.add(new FieldError(fe.getField(), fe.getDefaultMessage()))
        );
        pd.setProperty("errors", fieldErrors);

        return ResponseEntity.status(HttpStatus.BAD_REQUEST)
                .contentType(MediaType.APPLICATION_PROBLEM_JSON)
                .body(pd);
    }

    @ExceptionHandler(HttpMessageNotReadableException.class)
    public ResponseEntity<ProblemDetail> handleUnreadableBody(HttpMessageNotReadableException ex, HttpServletRequest req) {
        // Malformed JSON or a missing/null required field (e.g. an absent primitive) is a client
        // error, not a server error — return 400 instead of letting it fall through to the catch-all.
        log.debug("unreadable request body on {}: {}", req.getRequestURI(), ex.getMessage());
        ProblemDetail pd = ProblemDetail.forStatus(HttpStatus.BAD_REQUEST);
        pd.setTitle("Bad Request");
        pd.setDetail("request body is missing or malformed");
        pd.setType(ERR_VALIDATION);
        pd.setInstance(URI.create(req.getRequestURI()));
        return ResponseEntity.status(HttpStatus.BAD_REQUEST)
                .contentType(MediaType.APPLICATION_PROBLEM_JSON)
                .body(pd);
    }

    @ExceptionHandler(AccessDeniedException.class)
    public ResponseEntity<ProblemDetail> handleAccessDenied(AccessDeniedException ex, HttpServletRequest req) {
        ProblemDetail pd = ProblemDetail.forStatus(HttpStatus.FORBIDDEN);
        pd.setTitle("Forbidden");
        pd.setDetail("you do not have access to this resource");
        pd.setType(ERR_FORBIDDEN);
        pd.setInstance(URI.create(req.getRequestURI()));
        return ResponseEntity.status(HttpStatus.FORBIDDEN)
                .contentType(MediaType.APPLICATION_PROBLEM_JSON)
                .body(pd);
    }

    @ExceptionHandler(Exception.class)
    public ResponseEntity<ProblemDetail> handleAny(Exception ex, HttpServletRequest req) {
        log.error("Unhandled exception", ex);
        ProblemDetail pd = ProblemDetail.forStatus(HttpStatus.INTERNAL_SERVER_ERROR);
        pd.setTitle("Internal Server Error");
        pd.setDetail("unexpected error — see server logs");
        pd.setType(ERR_INTERNAL);
        pd.setInstance(URI.create(req.getRequestURI()));
        return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR)
                .contentType(MediaType.APPLICATION_PROBLEM_JSON)
                .body(pd);
    }

    private static String titleFor(HttpStatus status) {
        return switch (status) {
            case BAD_REQUEST -> "Bad Request";
            case UNAUTHORIZED -> "Unauthorized";
            case FORBIDDEN -> "Forbidden";
            case NOT_FOUND -> "Not Found";
            case CONFLICT -> "Conflict";
            case TOO_MANY_REQUESTS -> "Too Many Requests";
            default -> status.getReasonPhrase();
        };
    }

    private static URI typeFor(HttpStatus status) {
        return switch (status) {
            case BAD_REQUEST -> ERR_VALIDATION;
            case UNAUTHORIZED -> ERR_UNAUTHORIZED;
            case FORBIDDEN -> ERR_FORBIDDEN;
            case NOT_FOUND -> ERR_NOT_FOUND;
            case CONFLICT -> ERR_CONFLICT;
            case TOO_MANY_REQUESTS -> ERR_RATE_LIMITED;
            default -> ERR_INTERNAL;
        };
    }

    public record FieldError(String field, String message) {}
}
