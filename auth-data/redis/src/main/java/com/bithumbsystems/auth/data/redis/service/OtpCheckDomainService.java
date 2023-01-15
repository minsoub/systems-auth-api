package com.bithumbsystems.auth.data.redis.service;

import com.bithumbsystems.auth.data.redis.entity.OtpCheck;
import com.bithumbsystems.auth.data.redis.repository.OtpCheckRepository;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Service;
import reactor.core.publisher.Mono;

@Service
@Slf4j
@RequiredArgsConstructor
public class OtpCheckDomainService {
  private final OtpCheckRepository otpCheckRepository;

  public Mono<OtpCheck> findById(String id) {
    return otpCheckRepository.findById(id);
  }

  public Mono<OtpCheck> save(OtpCheck otpCheck) {
    return otpCheckRepository.save(otpCheck);
  }
}
