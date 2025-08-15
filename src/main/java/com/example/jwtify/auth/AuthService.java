package com.example.jwtify.auth;

import java.util.List;
import java.util.Map;

import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.stereotype.Service;

import com.example.jwtify.security.JwtService;
import com.example.jwtify.user.Role;
import com.example.jwtify.user.UserRepository;

import lombok.RequiredArgsConstructor;

@Service
@RequiredArgsConstructor
public class AuthService {
    private final UserRepository userRepository;
    private final BCryptPasswordEncoder encoder;
    private final AuthenticationManager authManager;
    private final JwtService jwt;

    public void register(RegisterRequest req) {
        if (userRepository.existsByEmail(req.getEmail()))
            throw new IllegalArgumentException("Email already in use");

        var user = com.example.jwtify.user.User.builder().email(req.getEmail())
                .password(encoder.encode(req.getPassword()))
                .role(Role.USER)
                .build();
        System.out.println(user);
        userRepository.save(user);
    }

    public AuthResponse login(AuthRequest req) {
        var authToken = new UsernamePasswordAuthenticationToken(req.getEmail(), req.getPassword());
        Authentication auth = authManager.authenticate(authToken);
        var userDetails = (UserDetails) auth.getPrincipal();
        var roles = userDetails.getAuthorities()
                .stream()
                .map(GrantedAuthority::getAuthority)
                .toList();
        System.out.println(roles);
        var claims = Map.of("roles", roles);
        System.out.println(claims);
        var access = jwt.generateAccessToken(req.getEmail(), claims);
        var refresh = jwt.generateRefreshToken(req.getEmail());
        return AuthResponse.builder().accessToken(access).refreshToken(refresh).build();
    }

    public AuthResponse refresh(String refreshToken) {
        if (!jwt.isValid(refreshToken))
            throw new IllegalArgumentException("Invalid refresh token");
        var email = jwt.getSubject(refreshToken);
        var role = "ROLE_" + userRepository.findByEmail(email).orElseThrow().getRole().name();
        var access = jwt.generateAccessToken(email, Map.of("roles", List.of(role)));
        return AuthResponse.builder().accessToken(access).refreshToken(refreshToken).build();
    }

}
