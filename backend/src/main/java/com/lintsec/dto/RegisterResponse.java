package com.lintsec.dto;

public record RegisterResponse(
        Long userId,
        boolean emailVerificationRequired
) {
}
