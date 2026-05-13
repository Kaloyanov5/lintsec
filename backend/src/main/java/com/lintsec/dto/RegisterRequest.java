package com.lintsec.dto;

import jakarta.validation.constraints.Email;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Pattern;
import jakarta.validation.constraints.Size;

public record RegisterRequest(

        @NotBlank
        @Email
        @Size(max = 254)
        String email,

        @NotBlank
        @Size(min = 10, max = 200)
        @Pattern(regexp = ".*[A-Za-z].*", message = "must contain a letter")
        @Pattern(regexp = ".*\\d.*", message = "must contain a digit")
        String password,

        @NotBlank
        @Size(min = 1, max = 100)
        String displayName
) {
}
