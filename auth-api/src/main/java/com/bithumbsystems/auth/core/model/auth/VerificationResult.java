package com.bithumbsystems.auth.core.model.auth;

import io.jsonwebtoken.Claims;
import lombok.AllArgsConstructor;
import lombok.Data;

@AllArgsConstructor
@Data
public class VerificationResult {

    public VerificationResult(Claims claims, String token) {
        this.claims = claims;
        this.token = token;
    }
    public Claims claims;
    public String token;
    public String requestUri;
    public String method;
    public String activeRole;
}
