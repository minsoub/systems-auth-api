package com.bithumbsystems.auth.api.exception.authorization;

import com.bithumbsystems.auth.core.model.enums.ErrorCode;
import org.springframework.http.HttpStatus;
import org.springframework.web.bind.annotation.ResponseStatus;

@ResponseStatus(value = HttpStatus.FORBIDDEN)
public class InvalidTokenException extends RuntimeException {
    public InvalidTokenException(ErrorCode errorCode) {
        super(String.valueOf(errorCode));
    }
}
