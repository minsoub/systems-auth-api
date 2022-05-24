package com.bithumbsystems.auth.data.redis;

import lombok.RequiredArgsConstructor;
import org.springframework.data.redis.core.ReactiveStringRedisTemplate;
import org.springframework.stereotype.Service;
import reactor.core.publisher.Mono;

@Service
@RequiredArgsConstructor
public class RedisTemplateSample {

  private final ReactiveStringRedisTemplate redisTemplate;

  public Mono<Long> saveToken(String userId, String token) {
    return redisTemplate.opsForList().leftPush(userId, token);
  }
}
