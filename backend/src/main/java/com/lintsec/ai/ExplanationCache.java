package com.lintsec.ai;

import com.lintsec.config.AiProperties;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.dao.DataAccessException;
import org.springframework.data.redis.core.StringRedisTemplate;
import org.springframework.stereotype.Component;

import java.time.Duration;
import java.util.Optional;

@Component
public class ExplanationCache {

    private static final String KEY_PREFIX = "lintsec:ai:explanation:";
    private static final Logger log = LoggerFactory.getLogger(ExplanationCache.class);

    private final StringRedisTemplate redis;
    private final Duration ttl;
    private final boolean enabled;

    public ExplanationCache(StringRedisTemplate redis, AiProperties props) {
        this.redis = redis;
        this.ttl = Duration.ofHours(props.cacheTtlHours());
        this.enabled = props.cacheTtlHours() > 0;
    }

    public Optional<String> get(String key) {
        if (!enabled) return Optional.empty();
        try {
            return Optional.ofNullable(redis.opsForValue().get(KEY_PREFIX + key));
        } catch (DataAccessException e) {
            log.warn("redis get failed for ai explanation: {}", e.getMessage());
            return Optional.empty();
        }
    }

    public void put(String key, String value) {
        if (!enabled) return;
        try {
            redis.opsForValue().set(KEY_PREFIX + key, value, ttl);
        } catch (DataAccessException e) {
            log.warn("redis put failed for ai explanation: {}", e.getMessage());
        }
    }
}
