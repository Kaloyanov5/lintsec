package com.lintsec.dto;

import com.lintsec.domain.AuthProvider;
import com.lintsec.domain.User;

import java.time.Instant;

public record UserDto(
        Long id,
        String email,
        String displayName,
        AuthProvider provider,
        boolean emailVerified,
        boolean twoFactorEnabled,
        Instant createdAt
) {
    public static UserDto from(User u) {
        return new UserDto(
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
