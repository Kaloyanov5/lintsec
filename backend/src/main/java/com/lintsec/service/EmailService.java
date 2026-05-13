package com.lintsec.service;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.mail.SimpleMailMessage;
import org.springframework.mail.javamail.JavaMailSender;
import org.springframework.stereotype.Service;

@Service
public class EmailService {

    private final JavaMailSender mailSender;
    private final String from;

    public EmailService(
            JavaMailSender mailSender,
            @Value("${lintsec.mail.from:no-reply@lintsec.local}") String from
    ) {
        this.mailSender = mailSender;
        this.from = from;
    }

    public void sendVerificationCode(String to, String code) {
        SimpleMailMessage msg = new SimpleMailMessage();
        msg.setFrom(from);
        msg.setTo(to);
        msg.setSubject("LintSec — confirm your email");
        msg.setText("Your LintSec verification code is: " + code
                + "\n\nIt expires in 15 minutes. If you didn't request this, ignore this email.");
        mailSender.send(msg);
    }

    public void sendTwoFactorCode(String to, String code) {
        SimpleMailMessage msg = new SimpleMailMessage();
        msg.setFrom(from);
        msg.setTo(to);
        msg.setSubject("LintSec — your sign-in code");
        msg.setText("Your LintSec sign-in code is: " + code
                + "\n\nIt expires in 10 minutes. If you didn't try to sign in, change your password.");
        mailSender.send(msg);
    }

    public void sendTwoFactorEnableCode(String to, String code) {
        SimpleMailMessage msg = new SimpleMailMessage();
        msg.setFrom(from);
        msg.setTo(to);
        msg.setSubject("LintSec — confirm 2FA activation");
        msg.setText("Enter this code in LintSec to enable two-factor authentication: " + code
                + "\n\nIt expires in 10 minutes.");
        mailSender.send(msg);
    }
}
