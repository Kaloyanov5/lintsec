package com.lintsec.ai;

import com.lintsec.config.AiProperties;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.http.MediaType;
import org.springframework.http.client.SimpleClientHttpRequestFactory;
import org.springframework.stereotype.Component;
import org.springframework.web.client.RestClient;

import java.util.List;
import java.util.Optional;

@Component
public class GeminiClient {
    private static final Logger log = LoggerFactory.getLogger(GeminiClient.class);
    private static final String DEFAULT_GEMINI_BASE_URL = "https://generativelanguage.googleapis.com/v1beta";

    private final AiProperties aiProperties;
    private final RestClient restClient;

    public GeminiClient(AiProperties aiProperties, RestClient.Builder builder) {
        this.aiProperties = aiProperties;

        SimpleClientHttpRequestFactory requestFactory = new SimpleClientHttpRequestFactory();
        requestFactory.setConnectTimeout(20_000);
        requestFactory.setReadTimeout(20_000);

        this.restClient = builder
                .baseUrl(DEFAULT_GEMINI_BASE_URL)
                .requestFactory(requestFactory)
                .build();
    }

    public Optional<String> explain(String prompt) {
        String apiKey = aiProperties.geminiApiKey();
        if (apiKey == null || apiKey.isBlank()) return Optional.empty();

        try {
            GeminiRequest request = new GeminiRequest(
                    List.of(new Content(List.of(new Part(prompt)))),
                    new GenerationConfig(0.2, 300)
            );

            GeminiResponse response = restClient.post()
                    .uri("/models/{model}:generateContent?key={key}", aiProperties.model(), apiKey)
                    .contentType(MediaType.APPLICATION_JSON)
                    .body(request)
                    .retrieve()
                    .body(GeminiResponse.class);

            if (response == null || response.candidates() == null || response.candidates().isEmpty()) {
                log.debug("gemini returned no candidates (blocked or empty)");
                return Optional.empty();
            }
            return Optional.of(response.candidates().getFirst().content().parts().getFirst().text());
        } catch (Exception e) {
            log.warn("gemini call failed: {}", e.getMessage());
            return Optional.empty();
        }
    }

    private record GeminiRequest(List<Content> contents, GenerationConfig generationConfig) {}
    private record Content(List<Part> parts) {}
    private record Part(String text) {}
    private record GenerationConfig(double temperature, int maxOutputTokens) {}
    private record GeminiResponse(List<Candidate> candidates) {}
    private record Candidate(Content content) {}
}
