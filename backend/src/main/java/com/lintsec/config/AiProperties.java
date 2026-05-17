package com.lintsec.config;

import org.springframework.boot.context.properties.ConfigurationProperties;

@ConfigurationProperties(prefix = "lintsec.ai")
public record AiProperties(
        String provider,
        String geminiApiKey,
        String model,
        int cacheTtlHours
) {
    public AiProperties {
        if (provider == null || provider.isBlank()) throw new IllegalArgumentException("provider must not be blank");
        if (model == null || model.isBlank()) throw new IllegalArgumentException("model must not be blank");
        if (cacheTtlHours < 0) throw new IllegalArgumentException("cacheTtlHours must be non-negative");
    }
}
