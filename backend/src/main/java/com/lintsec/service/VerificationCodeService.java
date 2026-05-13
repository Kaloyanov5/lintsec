package com.lintsec.service;

import org.springframework.data.redis.core.StringRedisTemplate;
import org.springframework.stereotype.Service;

import java.security.SecureRandom;
import java.time.Duration;

/**
 * Stores short-lived 6-digit codes in Redis with an attempt counter.
 * Keys live under namespaces like "lintsec:vcode:{purpose}:{subject}".
 */
@Service
public class VerificationCodeService {

    public enum Purpose {
        EMAIL_VERIFY("email-verify", Duration.ofMinutes(15)),
        LOGIN_2FA("login-2fa", Duration.ofMinutes(10)),
        ENABLE_2FA("enable-2fa", Duration.ofMinutes(10));

        final String key;
        final Duration ttl;

        Purpose(String key, Duration ttl) {
            this.key = key;
            this.ttl = ttl;
        }
    }

    public enum CheckResult {
        OK,
        WRONG,
        EXPIRED,
        TOO_MANY_ATTEMPTS
    }

    private static final int MAX_ATTEMPTS = 5;
    private static final SecureRandom RNG = new SecureRandom();

    private final StringRedisTemplate redis;

    public VerificationCodeService(StringRedisTemplate redis) {
        this.redis = redis;
    }

    public String issue(Purpose purpose, String subject) {
        String code = generateCode();
        redis.opsForValue().set(codeKey(purpose, subject), code, purpose.ttl);
        redis.delete(attemptKey(purpose, subject));
        return code;
    }

    public CheckResult verify(Purpose purpose, String subject, String submittedCode) {
        String stored = redis.opsForValue().get(codeKey(purpose, subject));
        if (stored == null) {
            return CheckResult.EXPIRED;
        }

        Long attempts = redis.opsForValue().increment(attemptKey(purpose, subject));
        if (attempts == null) {
            attempts = 1L;
        }
        if (attempts == 1L) {
            redis.expire(attemptKey(purpose, subject), purpose.ttl);
        }
        if (attempts > MAX_ATTEMPTS) {
            invalidate(purpose, subject);
            return CheckResult.TOO_MANY_ATTEMPTS;
        }

        if (!stored.equals(submittedCode)) {
            return CheckResult.WRONG;
        }

        invalidate(purpose, subject);
        return CheckResult.OK;
    }

    public void invalidate(Purpose purpose, String subject) {
        redis.delete(codeKey(purpose, subject));
        redis.delete(attemptKey(purpose, subject));
    }

    private static String generateCode() {
        int n = RNG.nextInt(1_000_000);
        return String.format("%06d", n);
    }

    private static String codeKey(Purpose purpose, String subject) {
        return "lintsec:vcode:" + purpose.key + ":" + subject;
    }

    private static String attemptKey(Purpose purpose, String subject) {
        return "lintsec:vcode:" + purpose.key + ":" + subject + ":attempts";
    }
}
