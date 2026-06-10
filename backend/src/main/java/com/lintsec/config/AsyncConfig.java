package com.lintsec.config;

import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.scheduling.annotation.EnableAsync;
import org.springframework.scheduling.concurrent.ThreadPoolTaskExecutor;

import java.util.concurrent.ThreadPoolExecutor;

@Configuration
@EnableAsync
@EnableConfigurationProperties(ScanProperties.class)
public class AsyncConfig {

    /**
     * Runs scans. Bounded on purpose: a bare {@code @EnableAsync} uses an executor with an
     * effectively unbounded queue, so a user could enqueue hundreds of scans and exhaust memory /
     * hammer targets. The per-user active-scan cap (see ScanService) is the first line; this pool
     * is the global ceiling. CallerRunsPolicy applies backpressure if both are somehow exceeded.
     */
    @Bean("scanExecutor")
    public ThreadPoolTaskExecutor scanExecutor() {
        ThreadPoolTaskExecutor executor = new ThreadPoolTaskExecutor();
        executor.setCorePoolSize(2);
        executor.setMaxPoolSize(4);
        executor.setQueueCapacity(25);
        executor.setThreadNamePrefix("scan-");
        executor.setRejectedExecutionHandler(new ThreadPoolExecutor.CallerRunsPolicy());
        executor.initialize();
        return executor;
    }

    /**
     * Runs post-scan AI explanation fan-out. Isolated from {@link #scanExecutor()} so its
     * deliberate per-call pacing (and any slow Gemini calls) can never starve scan execution.
     */
    @Bean("aiExecutor")
    public ThreadPoolTaskExecutor aiExecutor() {
        ThreadPoolTaskExecutor executor = new ThreadPoolTaskExecutor();
        executor.setCorePoolSize(1);
        executor.setMaxPoolSize(2);
        executor.setQueueCapacity(50);
        executor.setThreadNamePrefix("ai-");
        executor.setRejectedExecutionHandler(new ThreadPoolExecutor.CallerRunsPolicy());
        executor.initialize();
        return executor;
    }
}
