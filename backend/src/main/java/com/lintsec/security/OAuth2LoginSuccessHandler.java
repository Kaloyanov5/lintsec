package com.lintsec.security;

import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.core.Authentication;
import org.springframework.security.web.authentication.SimpleUrlAuthenticationSuccessHandler;
import org.springframework.stereotype.Component;

import java.io.IOException;

/**
 * After a successful Google login the principal is already an {@link AppUserPrincipal} (set by
 * {@link AppOidcUserService}) and the OAuth2AuthenticationToken is persisted by the login filter,
 * so this handler only needs to bounce the browser back to the frontend callback.
 */
@Component
public class OAuth2LoginSuccessHandler extends SimpleUrlAuthenticationSuccessHandler {

    private final String frontendBaseUrl;

    public OAuth2LoginSuccessHandler(
            @Value("${lintsec.frontend.base-url:http://localhost:5173}") String frontendBaseUrl
    ) {
        this.frontendBaseUrl = frontendBaseUrl;
    }

    @Override
    public void onAuthenticationSuccess(HttpServletRequest request,
                                        HttpServletResponse response,
                                        Authentication authentication) throws IOException, ServletException {
        getRedirectStrategy().sendRedirect(request, response, frontendBaseUrl + "/auth/callback");
    }
}
