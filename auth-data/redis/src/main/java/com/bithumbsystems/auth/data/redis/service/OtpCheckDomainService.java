package com.bithumbsystems.auth.data.redis.service;

import com.bithumbsystems.auth.data.redis.entity.OtpCheck;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.data.redis.core.ReactiveStringRedisTemplate;
import org.springframework.stereotype.Service;
import reactor.core.publisher.Mono;

@Service
@Slf4j
@RequiredArgsConstructor
public class OtpCheckDomainService {

  private final ReactiveStringRedisTemplate redisTemplate;

  public Mono<String> findById(String id) {
    return redisTemplate.opsForValue().get(id);
  }

  public Mono<Boolean> save(OtpCheck otpCheck) {
    log.info(otpCheck.toString());
    return redisTemplate.opsForValue().set(otpCheck.getId(), otpCheck.getFailCount());
  }
}
