package com.bithumbsystems.auth.api.exception;

import org.springframework.http.HttpStatus;
import org.springframework.web.bind.annotation.ResponseStatus;

@ResponseStatus(value = HttpStatus.FORBIDDEN)
public class NotExistAccountException extends ApiException {
    public NotExistAccountException(String message) {
        super(message, "NOT EXIST ACCOUNT");
    }
}
