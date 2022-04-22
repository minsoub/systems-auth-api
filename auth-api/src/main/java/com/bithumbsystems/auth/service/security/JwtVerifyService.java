package com.bithumbsystems.auth.service.security;

import com.bithumbsystems.auth.api.configuration.security.auth.AuthProperties;
import com.bithumbsystems.auth.api.exception.security.UnauthorizedException;
import com.bithumbsystems.auth.core.model.auth.VerificationResult;
import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Component;
import org.springframework.stereotype.Service;
import reactor.core.publisher.Mono;

import java.util.Base64;
import java.util.Date;

@Service
@RequiredArgsConstructor
public class JwtVerifyService {

    private AuthProperties authProperties;

    public Mono<VerificationResult> check(String token) {
        return Mono.just(verify(token))
                .onErrorResume(e -> Mono.error(new UnauthorizedException(e.getMessage())));
    }

    private VerificationResult verify(String token) {
        var claims = getAllClaimsFromToken(token);
        final Date expiration = claims.getExpiration();

        if (expiration.before(new Date()))
            throw new UnauthorizedException("Token expired");

        return new VerificationResult(claims, token);
    }

    public Claims getAllClaimsFromToken(String token) {
        return Jwts.parserBuilder()
                .setSigningKey(Base64.getEncoder().encodeToString(authProperties.getSecret().getBytes()))
                .build()
                .parseClaimsJws(token)
                .getBody();
    }
}

