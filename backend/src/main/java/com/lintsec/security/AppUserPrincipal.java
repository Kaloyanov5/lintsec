package com.lintsec.security;

import com.lintsec.domain.AuthProvider;
import com.lintsec.domain.User;

import java.io.Serializable;
import java.time.Instant;

public record AppUserPrincipal(
        Long id,
        String email,
        String displayName,
        AuthProvider provider,
        boolean emailVerified,
        boolean twoFactorEnabled,
        Instant createdAt
) implements Serializable {

    public static AppUserPrincipal from(User u) {
        return new AppUserPrincipal(
                u.getId(),
                u.getEmail(),
                u.getDisplayName(),
                u.getProvider(),
                u.isEmailVerified(),
                u.isTwoFactorEnabled(),
                u.getCreatedAt()
        );
    }
}
