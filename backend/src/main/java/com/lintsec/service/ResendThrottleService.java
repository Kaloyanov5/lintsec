package com.lintsec.service;

import org.springframework.data.redis.core.StringRedisTemplate;
import org.springframework.stereotype.Service;

import java.time.Duration;
import java.util.concurrent.TimeUnit;

/**
 * Enforces 1-per-minute resend rate on verification emails.
 */
@Service
public class ResendThrottleService {

    private static final Duration COOLDOWN = Duration.ofMinutes(1);

    private final StringRedisTemplate redis;

    public ResendThrottleService(StringRedisTemplate redis) {
        this.redis = redis;
    }

    /**
     * @return true if the caller may send now, false if still in cooldown.
     */
    public boolean tryAcquire(String email) {
        Boolean ok = redis.opsForValue().setIfAbsent(key(email), "1", COOLDOWN);
        return Boolean.TRUE.equals(ok);
    }

    public long retryAfterSeconds(String email) {
        Long ttl = redis.getExpire(key(email), TimeUnit.SECONDS);
        return (ttl == null || ttl < 0) ? 0L : ttl;
    }

    private static String key(String email) {
        return "lintsec:resend:" + email.toLowerCase();
    }
}
