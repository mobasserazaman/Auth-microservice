package com.example.jwtify.security;

import java.util.Date;
import java.util.Map;

import javax.crypto.SecretKey;

import org.springframework.stereotype.Service;

import com.example.jwtify.config.JwtProperties;

import io.jsonwebtoken.JwtException;
import io.jsonwebtoken.JwtParser;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.security.Keys;

@Service
public class JwtService {

    private final SecretKey key;
    private final Long accessTokenExpirationMs;
    private final Long refreshTokenExpirationMs;

    public JwtService(JwtProperties jwtProperties) {
        this.key = Keys.hmacShaKeyFor(jwtProperties.getSecret().getBytes());
        this.accessTokenExpirationMs = jwtProperties.getAccessTokenExpirationMs();
        this.refreshTokenExpirationMs = jwtProperties.getRefreshTokenExpirationMs();
    }

    private String buildToken(String subject, Map<String, String> claims, long expirationMs) {
        long now = System.currentTimeMillis();
        return Jwts.builder().subject(subject).claims(claims).issuedAt(new Date(now))
                .expiration(new Date(now + expirationMs))
                .signWith(key).compact();
    }

    public String generateAccessToken(String subject, Map<String, String> claims) {
        return buildToken(subject, claims, accessTokenExpirationMs);
    }

    public String generateRefreshToken(String subject) {
        return buildToken(subject, Map.of("type", "refresh"), refreshTokenExpirationMs);
    }

    private JwtParser parser() {
        return Jwts.parser().verifyWith(key).build();
    }

    public String getSubject(String token) {
        return parser().parseUnsecuredClaims(token).getPayload().getSubject();
    }

    public boolean isValid(String token) {
        try {
            parser().parseUnsecuredClaims(token);
            return true;
        } catch (JwtException | IllegalArgumentException e) {
            return false;
        }
    }

}
