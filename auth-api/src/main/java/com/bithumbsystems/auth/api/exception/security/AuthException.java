package com.bithumbsystems.auth.api.exception.security;

import com.bithumbsystems.auth.api.exception.ApiException;

public class AuthException extends ApiException {
    public AuthException(String message, String errorCode) {
        super(message, errorCode);
    }
}
