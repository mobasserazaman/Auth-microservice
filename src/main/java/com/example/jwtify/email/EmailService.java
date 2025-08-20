package com.example.jwtify.email;

import org.springframework.mail.SimpleMailMessage;
import org.springframework.mail.javamail.JavaMailSender;
import org.springframework.stereotype.Service;

import lombok.RequiredArgsConstructor;

@Service
@RequiredArgsConstructor
public class EmailService {

    private final JavaMailSender mailSender;

    public void sendPasswordResetEmail(String to, String token){
        String resetLink = "http://localhost:8080/api/auth/reset-password?token=" + token + "&email=" + to;
        SimpleMailMessage message = new SimpleMailMessage();
        message.setTo(to);
        message.setSubject("Password Reset Request");
        message.setText("Click the link to reset your password: " + resetLink);
        mailSender.send(message);
    }

    public void sendVerificationEmail(String to, String token){
        String verificationLink = "http://localhost:8080/api/auth/verify-email?token=" + token + "&email=" + to;
        SimpleMailMessage message = new SimpleMailMessage();
        message.setTo(to);
        message.setSubject("Verification Request");
        message.setText("Click the link to verify your email: " + verificationLink);
        mailSender.send(message);
    }
    
}
