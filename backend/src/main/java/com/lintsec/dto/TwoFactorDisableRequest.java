package com.lintsec.dto;

import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Size;

public record TwoFactorDisableRequest(

        @NotBlank
        @Size(max = 200)
        String password
) {
}
