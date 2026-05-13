package com.lintsec.dto;

import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Pattern;
import jakarta.validation.constraints.Size;

public record TwoFactorVerifyRequest(

        @NotBlank
        @Size(max = 64)
        String challengeId,

        @NotBlank
        @Pattern(regexp = "\\d{6}", message = "must be a 6-digit code")
        String code
) {
}
