package com.bithumbsystems.auth.core.model.response;

import com.bithumbsystems.auth.api.exception.ErrorData;
import com.bithumbsystems.auth.core.model.enums.ResultCode;
import lombok.AllArgsConstructor;
import lombok.Getter;

@Getter
@AllArgsConstructor
public class ErrorResponse {

  private final ResultCode result;
  private final ErrorData data;

  public ErrorResponse(ErrorData data) {
    this.result = ResultCode.ERROR;
    this.data = data;
  }
}