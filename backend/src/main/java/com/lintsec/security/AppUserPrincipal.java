package com.lintsec.security;

import com.lintsec.domain.AuthProvider;
import com.lintsec.domain.User;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.oauth2.core.oidc.OidcIdToken;
import org.springframework.security.oauth2.core.oidc.OidcUserInfo;
import org.springframework.security.oauth2.core.oidc.user.OidcUser;

import java.io.Serializable;
import java.time.Instant;
import java.util.Collection;
import java.util.List;
import java.util.Map;

/**
 * The application's authenticated principal. It implements {@link OidcUser} so that a Google OIDC
 * login can carry it directly as the principal — that way {@code @AuthenticationPrincipal
 * AppUserPrincipal} resolves on OAuth requests exactly as it does for form login. For local
 * (form) logins the OIDC payload is empty/null.
 */
public record AppUserPrincipal(
        Long id,
        String email,
        String displayName,
        AuthProvider provider,
        boolean emailVerified,
        boolean twoFactorEnabled,
        Instant createdAt,
        Map<String, Object> attributes,
        OidcIdToken idToken,
        OidcUserInfo userInfo
) implements OidcUser, Serializable {

    /** Local / form-login principal: no OIDC payload. */
    public static AppUserPrincipal from(User u) {
        return new AppUserPrincipal(
                u.getId(),
                u.getEmail(),
                u.getDisplayName(),
                u.getProvider(),
                u.isEmailVerified(),
                u.isTwoFactorEnabled(),
                u.getCreatedAt(),
                Map.of(),
                null,
                null
        );
    }

    /** OIDC principal: the same app identity, carrying the Google OIDC payload so it is a valid OidcUser. */
    public static AppUserPrincipal fromOidc(User u, OidcUser oidc) {
        return new AppUserPrincipal(
                u.getId(),
                u.getEmail(),
                u.getDisplayName(),
                u.getProvider(),
                u.isEmailVerified(),
                u.isTwoFactorEnabled(),
                u.getCreatedAt(),
                oidc.getAttributes(),
                oidc.getIdToken(),
                oidc.getUserInfo()
        );
    }

    @Override
    public Collection<? extends GrantedAuthority> getAuthorities() {
        return List.of(new SimpleGrantedAuthority("ROLE_USER"));
    }

    @Override
    public Map<String, Object> getAttributes() {
        return attributes != null ? attributes : Map.of();
    }

    @Override
    public Map<String, Object> getClaims() {
        return idToken != null ? idToken.getClaims() : getAttributes();
    }

    @Override
    public OidcUserInfo getUserInfo() {
        return userInfo;
    }

    @Override
    public OidcIdToken getIdToken() {
        return idToken;
    }

    /** Stable principal name used by Spring's OAuth2AuthenticationToken. */
    @Override
    public String getName() {
        return email;
    }
}
