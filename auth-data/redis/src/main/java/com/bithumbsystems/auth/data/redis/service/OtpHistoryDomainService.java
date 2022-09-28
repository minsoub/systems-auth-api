package com.bithumbsystems.auth.data.redis.service;

import com.bithumbsystems.auth.data.redis.entity.OtpHistory;
import com.bithumbsystems.auth.data.redis.repository.OtpHistoryCacheRepository;
import java.util.List;
import java.util.Optional;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Service;

@Service
@Slf4j
@RequiredArgsConstructor
public class OtpHistoryDomainService {

  private final OtpHistoryCacheRepository otpHistoryCacheRepository;

  public Optional<OtpHistory> searchOtpHistory(String id) {
    return otpHistoryCacheRepository.findById(id);
  }

  public OtpHistory save(OtpHistory otpHistory) {
    return otpHistoryCacheRepository.save(otpHistory);
  }
}
