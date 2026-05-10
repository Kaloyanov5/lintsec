package com.lintsec.config;

import io.swagger.v3.oas.models.OpenAPI;
import io.swagger.v3.oas.models.info.Info;
import io.swagger.v3.oas.models.info.License;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

@Configuration
public class OpenApiConfig {

    @Bean
    public OpenAPI lintsecOpenAPI() {
        return new OpenAPI()
                .info(new Info()
                        .title("LintSec API")
                        .description("Web application security scanner — crawls a target URL, runs vulnerability scanners, returns findings with AI-powered explanations.")
                        .version("v0.1")
                        .license(new License().name("Proprietary")));
    }
}
