package com.lintsec.service;

import org.springframework.data.redis.core.StringRedisTemplate;
import org.springframework.stereotype.Service;

import java.time.Duration;
import java.util.concurrent.TimeUnit;

/**
 * Tracks failed login attempts per email. After 5 fails within the window, login is locked.
 */
@Service
public class LoginAttemptService {

    public static final int MAX_FAILED = 5;
    public static final Duration WINDOW = Duration.ofMinutes(15);

    private final StringRedisTemplate redis;

    public LoginAttemptService(StringRedisTemplate redis) {
        this.redis = redis;
    }

    public boolean isLocked(String email) {
        String count = redis.opsForValue().get(key(email));
        return count != null && Integer.parseInt(count) >= MAX_FAILED;
    }

    public long retryAfterSeconds(String email) {
        Long ttl = redis.getExpire(key(email), TimeUnit.SECONDS);
        return (ttl == null || ttl < 0) ? WINDOW.toSeconds() : ttl;
    }

    public void recordFailure(String email) {
        String k = key(email);
        Long count = redis.opsForValue().increment(k);
        if (count != null && count == 1L) {
            redis.expire(k, WINDOW);
        }
    }

    public void clear(String email) {
        redis.delete(key(email));
    }

    private static String key(String email) {
        return "lintsec:login:fails:" + email.toLowerCase();
    }
}
