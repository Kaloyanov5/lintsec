package com.lintsec.crawler;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Configuration;

/**
 * Pushes the {@code lintsec.scan.allow-private-targets} flag into {@link TargetGuard} at startup.
 * Default false; set true only under the dev profile so a developer can scan a local target
 * (e.g. {@code http://localhost:8081}). Lives in the same package to reach the package-private setter.
 */
@Configuration
class TargetGuardConfig {
    private static final Logger log = LoggerFactory.getLogger(TargetGuardConfig.class);

    TargetGuardConfig(@Value("${lintsec.scan.allow-private-targets:false}") boolean allowPrivateTargets) {
        TargetGuard.setAllowPrivateTargets(allowPrivateTargets);
        if (allowPrivateTargets) {
            log.warn("SSRF guard relaxed: internal/loopback/private scan targets are PERMITTED "
                    + "(lintsec.scan.allow-private-targets=true). For local development only — never in production.");
        }
    }
}
