package com.bithumbsystems.auth.core.model.enums;

import lombok.Getter;
import lombok.RequiredArgsConstructor;
import org.springframework.boot.autoconfigure.neo4j.Neo4jProperties;

@RequiredArgsConstructor
@Getter
public enum ErrorCode {
  INVALID_CLIENT("client is not registered."),
  EXPIRED_TOKEN("Token expired"),
  INVALID_TOKEN("Invalid token"),

  USER_ACCOUNT_DISABLE("Account disabled"),
  INVALID_USER_PASSWORD("Invalid user password!"),

  INVALID_ACCOUNT_CLOSED("Account is closed!!"),
  INVALID_USERNAME("Invalid user name"),

  INVALID_USER("Not ADMIN"),

  INVALID_OTP_NUMER("Invalid Otp Digit number (6)"),

  EXISTED_USER("User is existed."),

  CAPTCHA_FAIL("Fail captcha verify"),

  AUTHENTICATION_FAIL("Fail Authentication"),

  MAXIMUM_AUTH_ATTEMPTS_EXCEEDED("maximum authentication attempts exceeded"),
  MAXIMUM_AUTHENTICATION_FAIL("Maximum authentication fail.");

  private final String message;
}
