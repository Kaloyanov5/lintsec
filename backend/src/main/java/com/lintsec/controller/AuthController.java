package com.lintsec.controller;

import com.lintsec.dto.ChangePasswordRequest;
import com.lintsec.dto.LoginRequest;
import com.lintsec.dto.LoginResponse;
import com.lintsec.dto.RegisterRequest;
import com.lintsec.dto.RegisterResponse;
import com.lintsec.dto.ResendVerificationRequest;
import com.lintsec.dto.TwoFactorConfirmRequest;
import com.lintsec.dto.TwoFactorDisableRequest;
import com.lintsec.dto.TwoFactorVerifyRequest;
import com.lintsec.dto.UserDto;
import com.lintsec.dto.VerifyEmailRequest;
import com.lintsec.security.AppUserPrincipal;
import com.lintsec.service.AuthService;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import jakarta.validation.Valid;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/api/auth")
public class AuthController {

    private final AuthService authService;

    public AuthController(AuthService authService) {
        this.authService = authService;
    }

    @PostMapping("/register")
    public ResponseEntity<RegisterResponse> register(@Valid @RequestBody RegisterRequest req) {
        RegisterResponse resp = authService.register(req.email(), req.password(), req.displayName());
        return ResponseEntity.status(HttpStatus.CREATED).body(resp);
    }

    @PostMapping("/verify-email")
    public UserDto verifyEmail(@Valid @RequestBody VerifyEmailRequest req,
                               HttpServletRequest request,
                               HttpServletResponse response) {
        return authService.verifyEmail(req.email(), req.code(), request, response);
    }

    @PostMapping("/resend-verification")
    public ResponseEntity<Void> resend(@Valid @RequestBody ResendVerificationRequest req) {
        authService.resendVerification(req.email());
        return ResponseEntity.ok().build();
    }

    @PostMapping("/login")
    public LoginResponse login(@Valid @RequestBody LoginRequest req,
                               HttpServletRequest request,
                               HttpServletResponse response) {
        return authService.login(req.email(), req.password(), request, response);
    }

    @PostMapping("/2fa/verify")
    public UserDto verifyTwoFactor(@Valid @RequestBody TwoFactorVerifyRequest req,
                                   HttpServletRequest request,
                                   HttpServletResponse response) {
        return authService.verifyTwoFactor(req.challengeId(), req.code(), request, response);
    }

    @PostMapping("/2fa/enable")
    public ResponseEntity<Void> enableTwoFactor(@AuthenticationPrincipal AppUserPrincipal principal) {
        authService.requestEnableTwoFactor(principal.id());
        return ResponseEntity.ok().build();
    }

    @PostMapping("/2fa/confirm")
    public ResponseEntity<Void> confirmTwoFactor(@AuthenticationPrincipal AppUserPrincipal principal,
                                                 @Valid @RequestBody TwoFactorConfirmRequest req) {
        authService.confirmEnableTwoFactor(principal.id(), req.code());
        return ResponseEntity.ok().build();
    }

    @PostMapping("/2fa/disable")
    public ResponseEntity<Void> disableTwoFactor(@AuthenticationPrincipal AppUserPrincipal principal,
                                                 @Valid @RequestBody TwoFactorDisableRequest req) {
        authService.disableTwoFactor(principal.id(), req.password());
        return ResponseEntity.ok().build();
    }

    @PostMapping("/change-password")
    public ResponseEntity<Void> changePassword(@AuthenticationPrincipal AppUserPrincipal principal,
                                               @Valid @RequestBody ChangePasswordRequest req) {
        authService.changePassword(principal.id(), req.currentPassword(), req.newPassword());
        return ResponseEntity.ok().build();
    }

    @PostMapping("/logout")
    public ResponseEntity<Void> logout(HttpServletRequest request, HttpServletResponse response) {
        authService.logout(request, response);
        return ResponseEntity.ok().build();
    }
}
