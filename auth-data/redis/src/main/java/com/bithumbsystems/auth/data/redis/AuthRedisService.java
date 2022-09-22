package com.bithumbsystems.auth.data.redis;

import java.time.Duration;
import lombok.RequiredArgsConstructor;
import org.springframework.data.redis.core.ReactiveStringRedisTemplate;
import org.springframework.stereotype.Service;
import reactor.core.publisher.Mono;

/**
 * The type Auth redis service.
 */
@Service
@RequiredArgsConstructor
public class AuthRedisService{

  private final ReactiveStringRedisTemplate redisTemplate;

  /**
   * Redis Key 정보를 저장한다.
   *
   * @param userId the user id
   * @param token  the token
   * @return mono
   */
  public Mono<Boolean> saveToken(String userId, String token) {
    return save(userId, token);
  }

  /**
   * Key를 통해서 토큰 정보를 조회한다.
   *
   * @param userId the user id
   * @return token
   */
  public Mono<String> getToken(String userId) {
    return getValue(userId);
  }

  /**
   * key를 통해서 토큰 정보를 삭제한다.
   *
   * @param userId the user id
   * @return mono
   */
  public Mono<Boolean> deleteToken(String userId) {
    return delete(userId);
  }

  /**
   * Redis Key 정보를 저장한다.
   *
   * @param key   the key
   * @param value the value
   * @return the mono
   */
  public Mono<Boolean> save(String key, String value) {
    return redisTemplate.opsForValue().set(key, value);
  }

  /**
   * Redis Key 정보를 저장한다.
   *
   * @param otpNo        the otp no
   * @param encodeKey    the encode key
   * @param expireSecond the expire second
   * @return the mono
   */
  private Mono<Boolean> saveExpiration(String otpNo, String encodeKey, int expireSecond ) {
    return redisTemplate.opsForValue().set(encodeKey, otpNo, Duration.ofSeconds(expireSecond));
  }


  /**
   * Key를 통해서 정보를 조회한다.
   *
   * @param key the key
   * @return value value
   */
  private Mono<String> getValue(String key) {
    return redisTemplate.opsForValue().get(key);
  }

  /**
   * Key를 통해서 만료 정보를 조회한다.
   *
   * @param key the key
   * @return value expire
   */
  private Mono<Duration> getExpire(String key) {
    return redisTemplate.getExpire(key);
  }

  /**
   * key를 통해서 정보를 삭제한다.
   *
   * @param key the key
   * @return result mono
   */
  private Mono<Boolean> delete(String key) {
    return redisTemplate.opsForValue().delete(key);
  }
}
