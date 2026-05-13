package com.lintsec.security;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.HttpStatus;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.HttpStatusEntryPoint;
import org.springframework.security.web.authentication.www.BasicAuthenticationFilter;
import org.springframework.security.web.csrf.CookieCsrfTokenRepository;
import org.springframework.security.web.csrf.CsrfTokenRequestAttributeHandler;
import org.springframework.security.web.servlet.util.matcher.PathPatternRequestMatcher;
import org.springframework.web.cors.CorsConfiguration;
import org.springframework.web.cors.CorsConfigurationSource;
import org.springframework.web.cors.UrlBasedCorsConfigurationSource;

import java.util.List;

@Configuration
public class SecurityConfig {

    private final OAuth2LoginSuccessHandler oauth2SuccessHandler;
    private final String frontendBaseUrl;

    public SecurityConfig(
            OAuth2LoginSuccessHandler oauth2SuccessHandler,
            @Value("${lintsec.frontend.base-url:http://localhost:5173}") String frontendBaseUrl
    ) {
        this.oauth2SuccessHandler = oauth2SuccessHandler;
        this.frontendBaseUrl = frontendBaseUrl;
    }

    @Bean
    public SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
        PathPatternRequestMatcher.Builder pp = PathPatternRequestMatcher.withDefaults();

        CsrfTokenRequestAttributeHandler csrfHandler = new CsrfTokenRequestAttributeHandler();

        http
                .cors(cors -> cors.configurationSource(corsConfigurationSource()))
                .csrf(csrf -> csrf
                        .csrfTokenRepository(CookieCsrfTokenRepository.withHttpOnlyFalse())
                        .csrfTokenRequestHandler(csrfHandler)
                )
                .addFilterAfter(new CsrfCookieFilter(), BasicAuthenticationFilter.class)
                .sessionManagement(session -> session
                        .sessionCreationPolicy(SessionCreationPolicy.IF_REQUIRED)
                )
                .authorizeHttpRequests(auth -> auth
                        .requestMatchers(
                                "/error",
                                "/swagger-ui.html",
                                "/swagger-ui/**",
                                "/v3/api-docs",
                                "/v3/api-docs/**",
                                "/oauth2/**",
                                "/login/**"
                        ).permitAll()
                        .requestMatchers(
                                "/api/auth/register",
                                "/api/auth/login",
                                "/api/auth/verify-email",
                                "/api/auth/resend-verification",
                                "/api/auth/2fa/verify"
                        ).anonymous()
                        .anyRequest().authenticated()
                )
                .formLogin(form -> form.disable())
                .httpBasic(basic -> basic.disable())
                .oauth2Login(oauth2 -> oauth2.successHandler(oauth2SuccessHandler))
                .exceptionHandling(eh -> eh
                        .defaultAuthenticationEntryPointFor(
                                new HttpStatusEntryPoint(HttpStatus.UNAUTHORIZED),
                                pp.matcher("/api/**")
                        )
                );

        return http.build();
    }

    @Bean
    public CorsConfigurationSource corsConfigurationSource() {
        CorsConfiguration config = new CorsConfiguration();
        config.setAllowedOrigins(List.of(frontendBaseUrl));
        config.setAllowedMethods(List.of("GET", "POST", "PUT", "DELETE", "OPTIONS"));
        config.setAllowedHeaders(List.of("*"));
        config.setExposedHeaders(List.of("Content-Disposition"));
        config.setAllowCredentials(true);
        config.setMaxAge(3600L);

        UrlBasedCorsConfigurationSource source = new UrlBasedCorsConfigurationSource();
        source.registerCorsConfiguration("/**", config);
        return source;
    }
}
