package com.bithumbsystems.auth.core.model.enums;

import lombok.Getter;
import lombok.RequiredArgsConstructor;

@RequiredArgsConstructor
@Getter
public enum ErrorCode {
  INVALID_CLIENT("client is not registered."),
  EXPIRED_TOKEN("Token expired"),
  INVALID_TOKEN("Invalid token");

  private final String message;
}
