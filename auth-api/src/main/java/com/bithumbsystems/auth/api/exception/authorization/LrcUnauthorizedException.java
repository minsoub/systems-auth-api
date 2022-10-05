package com.bithumbsystems.auth.api.exception.authorization;


import com.bithumbsystems.auth.model.lrc.enums.ErrorCode;
import org.springframework.http.HttpStatus;
import org.springframework.web.bind.annotation.ResponseStatus;

@ResponseStatus(value = HttpStatus.UNAUTHORIZED)
public class LrcUnauthorizedException extends RuntimeException {
    public LrcUnauthorizedException(ErrorCode errorCode) {
        super(String.valueOf(errorCode));
    }
}