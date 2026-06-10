package com.lintsec.service;

import com.lintsec.domain.AuthProvider;
import com.lintsec.domain.User;
import com.lintsec.dto.LoginResponse;
import com.lintsec.dto.RegisterResponse;
import com.lintsec.dto.UserDto;
import com.lintsec.exception.BadRequestException;
import com.lintsec.exception.ConflictException;
import com.lintsec.exception.RateLimitedException;
import com.lintsec.exception.UnauthorizedException;
import com.lintsec.security.AppUserPrincipal;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import jakarta.servlet.http.HttpSession;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.SecurityContext;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.context.SecurityContextHolderStrategy;
import org.springframework.security.web.context.HttpSessionSecurityContextRepository;
import org.springframework.security.web.context.SecurityContextRepository;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.util.List;

/**
 * Orchestrates the register / verify / login / 2FA flows described in CONTRACT.md §3.
 */
@Service
public class AuthService {

    static final String AUTHORITY_USER = "ROLE_USER";

    private final UserService userService;
    private final EmailService emailService;
    private final VerificationCodeService codeService;
    private final TwoFactorChallengeStore twoFactorChallengeStore;
    private final LoginAttemptService loginAttemptService;
    private final ResendThrottleService resendThrottle;
    private final SecurityContextRepository securityContextRepository;
    private final SecurityContextHolderStrategy contextHolderStrategy;

    public AuthService(
            UserService userService,
            EmailService emailService,
            VerificationCodeService codeService,
            TwoFactorChallengeStore twoFactorChallengeStore,
            LoginAttemptService loginAttemptService,
            ResendThrottleService resendThrottle
    ) {
        this.userService = userService;
        this.emailService = emailService;
        this.codeService = codeService;
        this.twoFactorChallengeStore = twoFactorChallengeStore;
        this.loginAttemptService = loginAttemptService;
        this.resendThrottle = resendThrottle;
        this.securityContextRepository = new HttpSessionSecurityContextRepository();
        this.contextHolderStrategy = SecurityContextHolder.getContextHolderStrategy();
    }

    @Transactional
    public RegisterResponse register(String email, String rawPassword, String displayName) {
        if (userService.emailTaken(email)) {
            throw new ConflictException("email already registered");
        }
        User user = userService.registerLocal(email, rawPassword, displayName);
        String code = codeService.issue(VerificationCodeService.Purpose.EMAIL_VERIFY, email.toLowerCase());
        emailService.sendVerificationCode(email, code);
        return new RegisterResponse(user.getId(), true);
    }

    public UserDto verifyEmail(String email, String code, HttpServletRequest request, HttpServletResponse response) {
        User user = userService.findByEmail(email)
                .orElseThrow(() -> new BadRequestException("no pending verification for this email"));

        VerificationCodeService.CheckResult result = codeService.verify(
                VerificationCodeService.Purpose.EMAIL_VERIFY, email.toLowerCase(), code);

        switch (result) {
            case EXPIRED -> throw new BadRequestException("code expired — request a new one");
            case WRONG -> throw new BadRequestException("incorrect code");
            case TOO_MANY_ATTEMPTS -> throw new BadRequestException("too many attempts — request a new code");
            case OK -> { /* fall through */ }
        }

        userService.markEmailVerified(user.getId());
        User refreshed = userService.getById(user.getId());
        establishSession(refreshed, request, response);
        return UserDto.from(refreshed);
    }

    public void resendVerification(String email) {
        if (!resendThrottle.tryAcquire(email)) {
            throw new RateLimitedException(
                    "please wait before requesting another code",
                    resendThrottle.retryAfterSeconds(email)
            );
        }
        userService.findByEmail(email).ifPresent(user -> {
            if (user.isEmailVerified()) {
                return;
            }
            String code = codeService.issue(VerificationCodeService.Purpose.EMAIL_VERIFY, email.toLowerCase());
            emailService.sendVerificationCode(email, code);
        });
    }

    public LoginResponse login(String email, String password, HttpServletRequest request, HttpServletResponse response) {
        if (loginAttemptService.isLocked(email)) {
            throw new RateLimitedException(
                    "too many failed attempts — try again later",
                    loginAttemptService.retryAfterSeconds(email)
            );
        }

        User user = userService.findByEmail(email).orElse(null);
        if (user == null || user.getProvider() != AuthProvider.LOCAL || !userService.checkPassword(user, password)) {
            loginAttemptService.recordFailure(email);
            throw new UnauthorizedException("invalid email or password");
        }

        if (!user.isEmailVerified()) {
            // Return the SAME generic failure as a wrong password — otherwise a correct-password
            // submit on an unverified account is distinguishable, turning login into a password
            // oracle. Silently resend the verification code (throttled) so the legitimate owner,
            // who controls the inbox, can still finish verifying.
            codeService.issueIfNotCoolingDown(VerificationCodeService.Purpose.EMAIL_VERIFY, email.toLowerCase())
                    .ifPresent(code -> emailService.sendVerificationCode(user.getEmail(), code));
            loginAttemptService.recordFailure(email);
            throw new UnauthorizedException("invalid email or password");
        }

        loginAttemptService.clear(email);

        if (user.isTwoFactorEnabled()) {
            // Throttle re-issue so repeated logins can't flood the inbox or reset the 5-guess limit;
            // when throttled the prior code is still valid, so we proceed to the challenge regardless.
            codeService.issueIfNotCoolingDown(VerificationCodeService.Purpose.LOGIN_2FA, "uid:" + user.getId())
                    .ifPresent(code -> emailService.sendTwoFactorCode(user.getEmail(), code));
            String challengeId = twoFactorChallengeStore.createChallenge(user.getId());
            return LoginResponse.twoFactorChallenge(challengeId);
        }

        establishSession(user, request, response);
        return LoginResponse.complete(UserDto.from(user));
    }

    public UserDto verifyTwoFactor(String challengeId, String code, HttpServletRequest request, HttpServletResponse response) {
        Long userId = twoFactorChallengeStore.peek(challengeId)
                .orElseThrow(() -> new UnauthorizedException("challenge expired"));

        VerificationCodeService.CheckResult result = codeService.verify(
                VerificationCodeService.Purpose.LOGIN_2FA, "uid:" + userId, code);

        switch (result) {
            case EXPIRED -> throw new UnauthorizedException("code expired");
            case WRONG -> throw new UnauthorizedException("incorrect code");
            case TOO_MANY_ATTEMPTS -> {
                twoFactorChallengeStore.consume(challengeId);
                throw new UnauthorizedException("too many attempts");
            }
            case OK -> { /* fall through */ }
        }

        twoFactorChallengeStore.consume(challengeId);
        User user = userService.getById(userId);
        establishSession(user, request, response);
        return UserDto.from(user);
    }

    public void requestEnableTwoFactor(Long userId) {
        User user = userService.getById(userId);
        if (user.getProvider() != AuthProvider.LOCAL) {
            throw new BadRequestException("2FA is only available for local accounts");
        }
        if (user.isTwoFactorEnabled()) {
            throw new ConflictException("2FA already enabled");
        }
        String code = codeService.issueIfNotCoolingDown(VerificationCodeService.Purpose.ENABLE_2FA, "uid:" + userId)
                .orElseThrow(() -> new RateLimitedException("please wait before requesting another code", 60));
        emailService.sendTwoFactorEnableCode(user.getEmail(), code);
    }

    public void confirmEnableTwoFactor(Long userId, String code) {
        VerificationCodeService.CheckResult result = codeService.verify(
                VerificationCodeService.Purpose.ENABLE_2FA, "uid:" + userId, code);

        switch (result) {
            case EXPIRED -> throw new BadRequestException("code expired");
            case WRONG -> throw new BadRequestException("incorrect code");
            case TOO_MANY_ATTEMPTS -> throw new BadRequestException("too many attempts");
            case OK -> { /* fall through */ }
        }

        userService.setTwoFactor(userId, true);
    }

    public void disableTwoFactor(Long userId, String password) {
        User user = userService.getById(userId);
        if (!userService.checkPassword(user, password)) {
            throw new UnauthorizedException("wrong password");
        }
        userService.setTwoFactor(userId, false);
    }

    public void changePassword(Long userId, String currentPassword, String newPassword) {
        User user = userService.getById(userId);
        if (user.getProvider() != AuthProvider.LOCAL) {
            throw new BadRequestException("password change is only available for local accounts");
        }
        if (!userService.checkPassword(user, currentPassword)) {
            throw new UnauthorizedException("wrong password");
        }
        userService.updatePassword(userId, newPassword);
    }

    public void logout(HttpServletRequest request, HttpServletResponse response) {
        HttpSession session = request.getSession(false);
        if (session != null) {
            session.invalidate();
        }
        contextHolderStrategy.clearContext();
    }

    public void establishSession(User user, HttpServletRequest request, HttpServletResponse response) {
        // Rotate the session id on authentication to prevent fixation: a session id an attacker
        // planted in the victim's browser before login must not survive into the authenticated
        // session. If no session exists yet, saveContext below mints a fresh one (also un-fixed).
        if (request.getSession(false) != null) {
            request.changeSessionId();
        }
        AppUserPrincipal principal = AppUserPrincipal.from(user);
        Authentication auth = UsernamePasswordAuthenticationToken.authenticated(
                principal,
                null,
                List.of(new SimpleGrantedAuthority(AUTHORITY_USER))
        );
        SecurityContext context = contextHolderStrategy.createEmptyContext();
        context.setAuthentication(auth);
        contextHolderStrategy.setContext(context);
        securityContextRepository.saveContext(context, request, response);
    }
}
