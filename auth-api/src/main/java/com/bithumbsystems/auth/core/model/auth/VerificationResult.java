package com.bithumbsystems.auth.core.model.auth;

import io.jsonwebtoken.Claims;
import lombok.AllArgsConstructor;

@AllArgsConstructor
public class VerificationResult {
    public Claims claims;
    public String token;
}
