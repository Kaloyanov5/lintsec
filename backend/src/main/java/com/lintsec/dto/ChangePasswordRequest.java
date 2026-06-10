package com.lintsec.dto;

import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Pattern;
import jakarta.validation.constraints.Size;

public record ChangePasswordRequest(

        @NotBlank
        @Size(max = 200)
        String currentPassword,

        @NotBlank
        @Size(min = 10, max = 200)
        @Pattern(regexp = ".*[A-Za-z].*", message = "must contain a letter")
        @Pattern(regexp = ".*\\d.*", message = "must contain a digit")
        String newPassword
) {
}
