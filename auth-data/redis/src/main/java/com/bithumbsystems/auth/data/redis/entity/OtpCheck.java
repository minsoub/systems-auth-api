package com.bithumbsystems.auth.data.redis.entity;

import lombok.Builder;
import lombok.Data;
import org.springframework.data.annotation.Id;
import org.springframework.data.redis.core.RedisHash;

@Data
@Builder
@RedisHash(value = "otp-check")
public class OtpCheck {
  @Id
  private String id;

  private String failCount;
}
