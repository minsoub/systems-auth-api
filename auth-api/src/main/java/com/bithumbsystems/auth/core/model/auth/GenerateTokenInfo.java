package com.bithumbsystems.auth.core.model.auth;

import java.util.Map;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Getter;

@AllArgsConstructor
@Getter
@Builder
public class GenerateTokenInfo {

  private final String expiration;
  private final String refreshExpiration;
  private final Map<String, Object> claims;
  private final String issuer;
  private final String subject;
  private final String secret;
}
