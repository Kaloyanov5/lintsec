package com.lintsec.dto;

import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Pattern;

public record TwoFactorConfirmRequest(

        @NotBlank
        @Pattern(regexp = "\\d{6}", message = "must be a 6-digit code")
        String code
) {
}
