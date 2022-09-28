package com.bithumbsystems.auth.data.redis.entity;

import lombok.Builder;
import lombok.Data;
import org.springframework.data.annotation.Id;
import org.springframework.data.redis.core.RedisHash;

@Data
@Builder
@RedisHash(value = "otp-history", timeToLive = 60 * 1L)
public class OtpHistory {

  @Id
  private String id;
}
