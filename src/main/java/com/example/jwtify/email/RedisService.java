package com.example.jwtify.email;

import java.time.Duration;

import org.springframework.data.redis.core.RedisTemplate;
import org.springframework.stereotype.Service;

import lombok.RequiredArgsConstructor;

@Service
@RequiredArgsConstructor
public class RedisService {

    private final RedisTemplate<String, String> redisTemplate;

    public void save(String key, String val, long duration){
        redisTemplate.opsForValue().set(key, val, Duration.ofMinutes(duration));
    }

    public String retrieve(String key){
        return redisTemplate.opsForValue().get(key);
    }

    public void deleteKey(String token) {
        redisTemplate.delete(token);
    }
}
