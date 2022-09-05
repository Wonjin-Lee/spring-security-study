package io.ader.security.basicsecurity.component;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.data.redis.core.RedisTemplate;
import org.springframework.data.redis.core.ValueOperations;
import org.springframework.stereotype.Component;

@Component
public class SessionStorageSample {
    @Autowired
    private RedisTemplate<String, String> redisTemplate;

    public void saveSession(String token, String sessionId) {
        ValueOperations<String, String> valueOperations = redisTemplate.opsForValue();
        valueOperations.set(token, sessionId);
    }
}
