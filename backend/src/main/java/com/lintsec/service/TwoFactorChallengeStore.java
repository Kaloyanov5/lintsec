package com.lintsec.service;

import org.springframework.data.redis.core.StringRedisTemplate;
import org.springframework.stereotype.Service;

import java.time.Duration;
import java.util.Optional;
import java.util.UUID;

/**
 * Holds the in-flight "user has passed password but still needs 2FA code" state.
 * The challengeId is returned to the client; the user id is kept server-side.
 */
@Service
public class TwoFactorChallengeStore {

    private static final Duration TTL = Duration.ofMinutes(10);

    private final StringRedisTemplate redis;

    public TwoFactorChallengeStore(StringRedisTemplate redis) {
        this.redis = redis;
    }

    public String createChallenge(Long userId) {
        String challengeId = UUID.randomUUID().toString();
        redis.opsForValue().set(key(challengeId), userId.toString(), TTL);
        return challengeId;
    }

    public Optional<Long> consume(String challengeId) {
        String key = key(challengeId);
        String userIdStr = redis.opsForValue().get(key);
        if (userIdStr == null) {
            return Optional.empty();
        }
        redis.delete(key);
        try {
            return Optional.of(Long.parseLong(userIdStr));
        } catch (NumberFormatException e) {
            return Optional.empty();
        }
    }

    public Optional<Long> peek(String challengeId) {
        String userIdStr = redis.opsForValue().get(key(challengeId));
        if (userIdStr == null) {
            return Optional.empty();
        }
        try {
            return Optional.of(Long.parseLong(userIdStr));
        } catch (NumberFormatException e) {
            return Optional.empty();
        }
    }

    private static String key(String challengeId) {
        return "lintsec:2fa:challenge:" + challengeId;
    }
}
