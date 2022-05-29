package com.bithumbsystems.auth.data.redis;

import lombok.RequiredArgsConstructor;
import org.springframework.data.redis.core.ReactiveStringRedisTemplate;
import org.springframework.stereotype.Service;
import reactor.core.publisher.Mono;

@Service
@RequiredArgsConstructor
public class RedisTemplateSample {

  private final ReactiveStringRedisTemplate redisTemplate;

  /**
   * Redis Key 정보를 저장한다.
   *
   * @param userId
   * @param token
   * @return
   */
  public Mono<Boolean> saveToken(String userId, String token) {
    //return redisTemplate.opsForList().leftPush(userId, token);
    return redisTemplate.opsForValue().set(userId, token);
  }

  /**
   * Key를 통해서 토큰 정보를 조회한다.
   *
   * @param userId
   * @return
   */
  public Mono<String> getToken(String userId) {
    return redisTemplate.opsForValue().get(userId);
  }

  /**
   * key를 통해서 토큰 정보를 삭제한다.
   *
   * @param userId
   * @return
   */
  public Mono<Boolean> deleteToken(String userId) {
    return redisTemplate.opsForValue().delete(userId);
  }


}
