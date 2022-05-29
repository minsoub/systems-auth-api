package com.bithumbsystems.auth.api.exception.authorization;

import com.bithumbsystems.auth.core.model.enums.ErrorCode;
import org.springframework.http.HttpStatus;
import org.springframework.web.bind.annotation.ResponseStatus;

@ResponseStatus(value = HttpStatus.UNAUTHORIZED)
public class UnauthorizedException extends RuntimeException {
    public UnauthorizedException(ErrorCode errorCode) {
        super(String.valueOf(errorCode));
    }

    /**
     * Token 검증 시 알 수 없는 예외 오류가 발생했을 때 - 잘 못된 토큰.
     */
    public UnauthorizedException() {
        super(String.valueOf(ErrorCode.INVALID_TOKEN));
    }
}