package com.lintsec.security;

import com.lintsec.domain.User;
import com.lintsec.exception.ApiException;
import com.lintsec.service.AuthService;
import com.lintsec.service.UserService;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.core.Authentication;
import org.springframework.security.oauth2.core.user.OAuth2User;
import org.springframework.security.web.authentication.SimpleUrlAuthenticationSuccessHandler;
import org.springframework.stereotype.Component;

import java.io.IOException;
import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;

@Component
public class OAuth2LoginSuccessHandler extends SimpleUrlAuthenticationSuccessHandler {

    private static final Logger log = LoggerFactory.getLogger(OAuth2LoginSuccessHandler.class);

    private final UserService userService;
    private final AuthService authService;
    private final String frontendBaseUrl;

    public OAuth2LoginSuccessHandler(
            UserService userService,
            AuthService authService,
            @Value("${lintsec.frontend.base-url:http://localhost:5173}") String frontendBaseUrl
    ) {
        this.userService = userService;
        this.authService = authService;
        this.frontendBaseUrl = frontendBaseUrl;
    }

    @Override
    public void onAuthenticationSuccess(HttpServletRequest request,
                                        HttpServletResponse response,
                                        Authentication authentication) throws IOException, ServletException {

        OAuth2User oauth2User = (OAuth2User) authentication.getPrincipal();
        String googleSub = oauth2User.getAttribute("sub");
        String email = oauth2User.getAttribute("email");
        String displayName = oauth2User.getAttribute("name");

        if (googleSub == null || email == null) {
            response.sendRedirect(frontendBaseUrl + "/auth/callback?error=oauth_missing_attributes");
            return;
        }

        User user;
        try {
            user = userService.upsertGoogleUser(googleSub, email, displayName);
        } catch (ApiException ex) {
            log.warn("OAuth2 upsert refused: {}", ex.getMessage());
            String encoded = URLEncoder.encode(ex.getMessage(), StandardCharsets.UTF_8);
            response.sendRedirect(frontendBaseUrl + "/auth/callback?error=email_conflict&message=" + encoded);
            return;
        }

        authService.establishSession(user, request, response);
        getRedirectStrategy().sendRedirect(request, response, frontendBaseUrl + "/auth/callback");
    }
}
