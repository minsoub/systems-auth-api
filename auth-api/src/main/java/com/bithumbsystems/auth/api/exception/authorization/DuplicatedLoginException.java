package com.bithumbsystems.auth.api.exception.authorization;

import com.bithumbsystems.auth.core.model.enums.ErrorCode;
import org.springframework.http.HttpStatus;
import org.springframework.web.bind.annotation.ResponseStatus;

@ResponseStatus(HttpStatus.CONFLICT)
public class DuplicatedLoginException extends RuntimeException {
  public DuplicatedLoginException(ErrorCode errorCode) {
    super(String.valueOf(errorCode));
  }
}
