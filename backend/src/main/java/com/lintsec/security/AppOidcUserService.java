package com.lintsec.security;

import com.lintsec.domain.User;
import com.lintsec.exception.ApiException;
import com.lintsec.service.UserService;
import org.springframework.security.oauth2.client.oidc.userinfo.OidcUserRequest;
import org.springframework.security.oauth2.client.oidc.userinfo.OidcUserService;
import org.springframework.security.oauth2.core.OAuth2AuthenticationException;
import org.springframework.security.oauth2.core.OAuth2Error;
import org.springframework.security.oauth2.core.oidc.user.OidcUser;
import org.springframework.stereotype.Service;

/**
 * Loads the Google OIDC user, upserts the matching application {@link User}, and returns an
 * {@link AppUserPrincipal} as the principal. Because this runs during authentication, the persisted
 * OAuth2AuthenticationToken carries our principal type — so {@code @AuthenticationPrincipal
 * AppUserPrincipal} works on every OAuth request without any post-login session retrofit.
 */
@Service
public class AppOidcUserService extends OidcUserService {

    private final UserService userService;

    public AppOidcUserService(UserService userService) {
        this.userService = userService;
    }

    @Override
    public OidcUser loadUser(OidcUserRequest userRequest) throws OAuth2AuthenticationException {
        OidcUser oidc = super.loadUser(userRequest);

        String sub = oidc.getSubject();
        String email = oidc.getEmail();
        String displayName = oidc.getFullName();

        if (sub == null || email == null) {
            throw new OAuth2AuthenticationException(
                    new OAuth2Error("oauth_missing_attributes"),
                    "Google did not return the required profile attributes");
        }

        try {
            User user = userService.upsertGoogleUser(sub, email, displayName);
            return AppUserPrincipal.fromOidc(user, oidc);
        } catch (ApiException ex) {
            // Surface app-level refusals (e.g. email already registered locally) as an OAuth failure
            // so the configured failure handler can redirect with a friendly error the frontend knows.
            throw new OAuth2AuthenticationException(
                    new OAuth2Error("email_conflict", ex.getMessage(), null), ex.getMessage());
        }
    }
}
