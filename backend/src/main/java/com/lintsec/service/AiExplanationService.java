package com.lintsec.service;

import com.lintsec.ai.ExplanationCache;
import com.lintsec.ai.FindingExplanationPromptBuilder;
import com.lintsec.ai.GeminiClient;
import com.lintsec.domain.Finding;
import org.springframework.stereotype.Service;

import java.util.Optional;

@Service
public class AiExplanationService {

    private final ExplanationCache cache;
    private final GeminiClient gemini;
    private final FindingExplanationPromptBuilder builder;

    public AiExplanationService(ExplanationCache cache, GeminiClient gemini, FindingExplanationPromptBuilder builder) {
        this.cache = cache;
        this.gemini = gemini;
        this.builder = builder;
    }

    public Optional<String> explain(Finding finding) {
        String key = cacheKey(finding);
        Optional<String> cached = cache.get(key);
        if (cached.isPresent()) return cached;

        Optional<String> explanation = gemini.explain(builder.build(finding));
        if (explanation.isEmpty()) return Optional.empty();
        explanation.ifPresent(text -> cache.put(key, text));
        return explanation;
    }

    private String cacheKey(Finding finding) {
        // Key on the finding's stable identity (type + severity), NOT the title. Titles embed
        // site-controlled values (e.g. a reflected parameter name), so keying on them gives an
        // unbounded, per-site key space with little reuse — and lets a hostile target spray cache
        // entries. The explanation is general to the vulnerability class, so this is also a better cache.
        return finding.getVulnerabilityType().name() + ":" + finding.getSeverity().name();
    }
}
