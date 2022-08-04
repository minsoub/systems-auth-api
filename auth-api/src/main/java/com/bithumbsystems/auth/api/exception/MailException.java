package com.bithumbsystems.auth.api.exception;

import com.bithumbsystems.auth.core.model.enums.ErrorCode;
import lombok.Getter;
import org.springframework.http.HttpStatus;
import org.springframework.web.bind.annotation.ResponseStatus;

@ResponseStatus(value = HttpStatus.UNAUTHORIZED)
@Getter
public class MailException extends RuntimeException {

    private final ErrorCode errorCode;

    public MailException(ErrorCode errorCode) {
        super(errorCode.getMessage());
        this.errorCode = errorCode;
    }
}
