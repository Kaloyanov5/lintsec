package com.lintsec.service;

import com.lintsec.domain.AuthProvider;
import com.lintsec.domain.User;
import com.lintsec.exception.BadRequestException;
import com.lintsec.exception.UnauthorizedException;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

import java.util.Optional;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

@ExtendWith(MockitoExtension.class)
class AuthServiceTest {

    @Mock UserService userService;
    @Mock EmailService emailService;
    @Mock VerificationCodeService codeService;
    @Mock TwoFactorChallengeStore twoFactorChallengeStore;
    @Mock LoginAttemptService loginAttemptService;
    @Mock ResendThrottleService resendThrottle;
    @InjectMocks AuthService authService;

    private static User localUser() {
        User u = new User();
        u.setId(1L);
        u.setProvider(AuthProvider.LOCAL);
        u.setPasswordHash("hashed");
        return u;
    }

    @Test
    void changePasswordUpdatesWhenCurrentMatches() {
        User user = localUser();
        when(userService.getById(1L)).thenReturn(user);
        when(userService.checkPassword(user, "oldpass")).thenReturn(true);

        authService.changePassword(1L, "oldpass", "NewPassw0rd");

        verify(userService).updatePassword(1L, "NewPassw0rd");
    }

    @Test
    void changePasswordWrongCurrentIsUnauthorized() {
        User user = localUser();
        when(userService.getById(1L)).thenReturn(user);
        when(userService.checkPassword(user, "wrong")).thenReturn(false);

        assertThrows(UnauthorizedException.class,
                () -> authService.changePassword(1L, "wrong", "NewPassw0rd"));
        verify(userService, never()).updatePassword(any(), any());
    }

    @Test
    void loginUnverifiedAccountReturnsGenericErrorAndResendsCode() {
        // Security: a correct password on an unverified account must NOT be distinguishable from a
        // wrong password, or login becomes a password oracle. The code is silently resent.
        User user = localUser();
        user.setEmail("user@x.com");
        user.setEmailVerified(false);
        when(loginAttemptService.isLocked("user@x.com")).thenReturn(false);
        when(userService.findByEmail("user@x.com")).thenReturn(Optional.of(user));
        when(userService.checkPassword(user, "correct")).thenReturn(true);
        when(codeService.issueIfNotCoolingDown(VerificationCodeService.Purpose.EMAIL_VERIFY, "user@x.com"))
                .thenReturn(Optional.of("123456"));

        UnauthorizedException ex = assertThrows(UnauthorizedException.class,
                () -> authService.login("user@x.com", "correct", null, null));

        assertEquals("invalid email or password", ex.getMessage());
        verify(emailService).sendVerificationCode("user@x.com", "123456");
        verify(loginAttemptService).recordFailure("user@x.com");
    }

    @Test
    void changePasswordRejectsNonLocalAccount() {
        User user = localUser();
        user.setProvider(AuthProvider.GOOGLE);
        when(userService.getById(1L)).thenReturn(user);

        assertThrows(BadRequestException.class,
                () -> authService.changePassword(1L, "x", "NewPassw0rd"));
        verify(userService, never()).updatePassword(any(), any());
    }
}
