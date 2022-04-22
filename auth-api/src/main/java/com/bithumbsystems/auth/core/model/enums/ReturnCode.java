package com.bithumbsystems.auth.core.model.enums;

import lombok.Getter;
import lombok.RequiredArgsConstructor;
import lombok.ToString;
import org.springframework.http.HttpStatus;

@Getter
@RequiredArgsConstructor
@ToString
public enum ReturnCode {
    SUCCESS("00000", "성공", HttpStatus.OK),
    INVALID_PARAMETERS("40001", "요청 파라미터에 문제가 있습니다.", HttpStatus.BAD_REQUEST),
    ERROR("50004", "오류가 발생 하였습니다. 시스템 관리자에게 문의해주세요.", HttpStatus.INTERNAL_SERVER_ERROR);

    private final String code;
    private final String message;
    private final HttpStatus status;
}