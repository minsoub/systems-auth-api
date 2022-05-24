package com.bithumbsystems.auth.api.exception;

import com.bithumbsystems.auth.core.model.enums.ErrorCode;
import lombok.Getter;

@Getter
public class ErrorData {
  private final String error;
  private final String message;

  public ErrorData(ErrorCode errorCode) {
    this.error = errorCode.name();
    this.message = errorCode.getMessage();
  }
}