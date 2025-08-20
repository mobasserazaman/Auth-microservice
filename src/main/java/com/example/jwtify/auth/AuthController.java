package com.example.jwtify.auth;

import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import io.swagger.v3.oas.annotations.Operation;
import lombok.RequiredArgsConstructor;

@RestController
@RequestMapping("/api/auth")
@RequiredArgsConstructor
public class AuthController {

    private final AuthService auth;

    @Operation(summary = "Register new user", description = "Registers a new account and sends verification email")
    @PostMapping("/register")
    public ResponseEntity<?> register(@RequestBody RegisterRequest req) {
        auth.register(req);
        return ResponseEntity.ok().build();
    }

    @Operation(summary = "Login user", description = "Logs in a user and returns JWT")
    @PostMapping("/login")
    public ResponseEntity<AuthResponse> login(@RequestBody AuthRequest req) {
        return ResponseEntity.ok(auth.login(req));
    }

    @Operation(summary = "Refresh access token", description = "Generates new access token. Access tokens are short lived and expire in 15 minutes for security")
    @PostMapping("/refresh")
    public ResponseEntity<AuthResponse> refresh(@RequestBody String refreshToken) {
        // If you prefer JSON: make a { "refreshToken": "..." } DTO instead of raw
        // string
        return ResponseEntity.ok(auth.refresh(refreshToken.replace("\"", "").trim()));
    }

    @Operation(summary = "Request password reset", description = "Requests a password reset for the account associated to the email")
    @PostMapping("/request-reset")
    public ResponseEntity<?> requestReset(@RequestParam String email) {
        auth.requestPasswordReset(email);
        return ResponseEntity.ok("Password reset link sent to email");
    }

    @Operation(summary = "Reset password", description = "The reset link sent when the user hits /request-reset contains the token and email")
    @PostMapping("/reset-password")
    public ResponseEntity<?> resetPassword(@RequestParam String token, @RequestParam String email,
            @RequestBody String newPassword) {
        auth.resetPassword(token, email, newPassword.replace("\"", "").trim());
        return ResponseEntity.ok("Password reset successful");
    }

    @Operation(summary = "Resend verification link", description = "Requests a new account verification link. Only verified user accounts can login")
    @PostMapping("/resend-verification")
    public ResponseEntity<?> resendVerification(@RequestParam String email) {
        auth.requestVerification(email);
        return ResponseEntity.ok("Verification link sent to email");
    }

    @Operation(summary = "Verify account", description = "The verfication link sent when the user hits /resend-verification contains the token and email")
    @PostMapping("/verify-email")
    public ResponseEntity<?> verifyEmail(@RequestParam String token, @RequestParam String email) {
        auth.verifyEmail(token, email);
        return ResponseEntity.ok("Verification successful");
    }

}