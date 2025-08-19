package com.example.jwtify.mail;

import java.time.Duration;

import org.springframework.data.redis.core.RedisTemplate;
import org.springframework.stereotype.Service;

import lombok.RequiredArgsConstructor;

@Service
@RequiredArgsConstructor
public class PasswordResetRedisService {

    private final RedisTemplate<String, String> redisTemplate;

    public void saveToken(String token, String email, long durationMinutes) {
        redisTemplate.opsForValue().set(token, email, Duration.ofMinutes(durationMinutes));
    }

    public String getEmailByToken(String token) {
        return redisTemplate.opsForValue().get(token);
    }

    public void deleteToken(String token) {
        redisTemplate.delete(token);
    }
}
