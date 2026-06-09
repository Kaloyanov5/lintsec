package com.lintsec.service;

import com.lintsec.domain.AuthProvider;
import com.lintsec.domain.User;
import com.lintsec.exception.ConflictException;
import com.lintsec.repository.UserRepository;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.util.Optional;

@Service
public class UserService {

    private final UserRepository userRepository;
    private final PasswordEncoder passwordEncoder;

    public UserService(UserRepository userRepository, PasswordEncoder passwordEncoder) {
        this.userRepository = userRepository;
        this.passwordEncoder = passwordEncoder;
    }

    public Optional<User> findByEmail(String email) {
        return userRepository.findByEmailIgnoreCase(email);
    }

    public User getById(Long id) {
        return userRepository.findById(id)
                .orElseThrow(() -> new IllegalStateException("User vanished: " + id));
    }

    public boolean emailTaken(String email) {
        return userRepository.existsByEmailIgnoreCase(email);
    }

    @Transactional
    public User registerLocal(String email, String rawPassword, String displayName) {
        User u = new User();
        u.setEmail(email);
        u.setPasswordHash(passwordEncoder.encode(rawPassword));
        u.setDisplayName(displayName);
        u.setProvider(AuthProvider.LOCAL);
        u.setEmailVerified(false);
        u.setTwoFactorEnabled(false);
        return userRepository.save(u);
    }

    @Transactional
    public User upsertGoogleUser(String googleSubjectId, String email, String displayName) {
        return userRepository.findByProviderAndProviderId(AuthProvider.GOOGLE, googleSubjectId)
                .orElseGet(() -> {
                    userRepository.findByEmailIgnoreCase(email).ifPresent(existing -> {
                        throw new ConflictException(
                                "an account with this email already exists — sign in with your password instead"
                        );
                    });
                    User u = new User();
                    u.setEmail(email);
                    u.setDisplayName(displayName);
                    u.setProvider(AuthProvider.GOOGLE);
                    u.setProviderId(googleSubjectId);
                    u.setEmailVerified(true);
                    u.setTwoFactorEnabled(false);
                    return userRepository.save(u);
                });
    }

    @Transactional
    public void markEmailVerified(Long userId) {
        User u = getById(userId);
        u.setEmailVerified(true);
    }

    @Transactional
    public void setTwoFactor(Long userId, boolean enabled) {
        User u = getById(userId);
        u.setTwoFactorEnabled(enabled);
    }

    @Transactional
    public void updatePassword(Long userId, String rawPassword) {
        User u = getById(userId);
        u.setPasswordHash(passwordEncoder.encode(rawPassword));
    }

    public boolean checkPassword(User user, String rawPassword) {
        if (user.getPasswordHash() == null) {
            return false;
        }
        return passwordEncoder.matches(rawPassword, user.getPasswordHash());
    }
}
