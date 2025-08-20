package com.example.jwtify.auth;

import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;
import lombok.RequiredArgsConstructor;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;



@RestController
@RequestMapping("/api/auth")
@RequiredArgsConstructor
public class AuthController {

    private final AuthService auth;

    @PostMapping("/register")
    public ResponseEntity<?> register(@RequestBody RegisterRequest req) {
        auth.register(req);
        return ResponseEntity.ok().build();
    }

    @PostMapping("/login")
    public ResponseEntity<AuthResponse> login(@RequestBody AuthRequest req) {
        return ResponseEntity.ok(auth.login(req));
    }

    @PostMapping("/refresh")
    public ResponseEntity<AuthResponse> refresh(@RequestBody String refreshToken) {
        // If you prefer JSON: make a { "refreshToken": "..." } DTO instead of raw
        // string
        return ResponseEntity.ok(auth.refresh(refreshToken.replace("\"", "").trim()));
    }

    @PostMapping("/request-reset")
    public ResponseEntity<?> requestReset(@RequestParam String email) {
        auth.requestPasswordReset(email);
        return ResponseEntity.ok("Password reset link sent to email");
    }

    @PostMapping("/reset-password")
    public ResponseEntity<?> resetPassword(@RequestParam String token, @RequestParam String email, @RequestBody String newPassword) {
        auth.resetPassword(token, email, newPassword.replace("\"", "").trim());
        return ResponseEntity.ok("Password reset successful");
    }

    @PostMapping("/resend-verification")
    public ResponseEntity<?> resendVerification(@RequestParam String email) {
        auth.requestVerification(email);
        return ResponseEntity.ok("Verification link send to email");
    }

    @PostMapping("/verify-email")
    public ResponseEntity<?> verifyEmail(@RequestParam String token, @RequestParam String email) {
        auth.verifyEmail(token, email);  
        return ResponseEntity.ok("Verification successful");
    }
    
    

}