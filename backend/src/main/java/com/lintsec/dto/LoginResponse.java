package com.lintsec.dto;

import com.fasterxml.jackson.annotation.JsonInclude;

@JsonInclude(JsonInclude.Include.NON_NULL)
public record LoginResponse(
        boolean twoFactorRequired,
        UserDto user,
        String challengeId
) {
    public static LoginResponse complete(UserDto user) {
        return new LoginResponse(false, user, null);
    }

    public static LoginResponse twoFactorChallenge(String challengeId) {
        return new LoginResponse(true, null, challengeId);
    }
}
