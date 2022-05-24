package com.bithumbsystems.auth.api.exception.authorization;

import com.bithumbsystems.auth.core.model.enums.ErrorCode;
import org.springframework.http.HttpStatus;
import org.springframework.web.bind.annotation.ResponseStatus;

@ResponseStatus(value = HttpStatus.UNAUTHORIZED)
public class UnauthorizedException extends RuntimeException {
    public UnauthorizedException(ErrorCode errorCode) {
        super(String.valueOf(errorCode));
    }
}