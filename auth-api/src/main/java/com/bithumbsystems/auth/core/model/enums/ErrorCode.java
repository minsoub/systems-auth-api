package com.bithumbsystems.auth.core.model.enums;

import lombok.Getter;
import lombok.RequiredArgsConstructor;

@RequiredArgsConstructor
@Getter
public enum ErrorCode {
  INVALID_CLIENT("client is not registered."),
  INVALID_HEADER_SITE_ID("Header 정보가 유효하지 않습니다!!(Not found site_id)"),
  EXPIRED_TOKEN("Token expired"),
  INVALID_TOKEN("Invalid token"),

  USER_ACCOUNT_DISABLE("Account disabled"),
  USER_ACCOUNT_EXPIRED("Account expired"),

  INVALID_USER_PASSWORD("Invalid user password!"),

  INVALID_ACCOUNT_CLOSED("Account is closed!!"),
  INVALID_USERNAME("Invalid user name"),

  INVALID_USER("Not ADMIN"),

  INVALID_OTP_NUMBER("Invalid Otp Digit number (6)"),

  EXISTED_USER("User is existed."),

  CAPTCHA_FAIL("Fail captcha verify"),

  AUTHENTICATION_FAIL("Fail Authentication"),

  MAXIMUM_AUTH_ATTEMPTS_EXCEEDED("maximum authentication attempts exceeded"),
  MAXIMUM_AUTHENTICATION_FAIL("Maximum authentication fail."),
  USER_ACCOUNT_EMAIL_VALID("Email verification required."),

  USER_ALREADY_LOGIN( "User is already login"),
  EXPIRED_PASSWORD("Password expired."),
  EQUAL_OLD_PASSWORD("New password is equal to old password."),
  FAIL_SEND_MAIL("FAIL_SEND_MAIL"),

  EQUAL_CURRENT_PASSWORD("New password is equal to current password."),

  LOGIN_USER_NOT_MATCHED("Login user not match");

  private final String message;
}
