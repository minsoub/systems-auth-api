package com.bithumbsystems.auth.service.security;

import com.bithumbsystems.auth.api.configuration.security.auth.AuthProperties;
import com.bithumbsystems.auth.core.model.auth.TokenInfo;
import com.bithumbsystems.auth.core.model.enums.TokenType;
import com.bithumbsystems.auth.data.mongodb.entity.Account;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.security.Keys;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Service;

import java.util.Date;
import java.util.HashMap;
import java.util.Map;
import java.util.UUID;

@Service
@RequiredArgsConstructor
public class JwtGenerateService {
    private AuthProperties authProperties;

    public TokenInfo generateAccessToken(Account account, TokenType tokenType) {
        var claims = new HashMap<String, Object>() {{
            put("role", account.getRoles());
        }};

        return doGenerateToken(claims, account.getEmail(), account.getId(), tokenType);
    }

    private TokenInfo doGenerateToken(Map<String, Object> claims, String issuer, String subject, TokenType tokenType) {
        var expirationTimeInMilliseconds = Long.parseLong(authProperties.getExpiration().get(tokenType.value())) * 1000;
        var expirationDate = new Date(new Date().getTime() + expirationTimeInMilliseconds);

        return doGenerateToken(expirationDate, claims, issuer, subject);
    }

    private TokenInfo doGenerateToken(Date expirationDate, Map<String, Object> claims, String issuer, String subject) {
        var createdDate = new Date();
        var token = Jwts.builder()
                .setClaims(claims)
                .setIssuer(issuer)
                .setSubject(subject)
                .setIssuedAt(createdDate)
                .setId(UUID.randomUUID().toString())
                .setExpiration(expirationDate)
                .signWith(Keys.hmacShaKeyFor(authProperties.getSecret().getBytes()))
                .compact();

        return TokenInfo.builder()
                .token(token)
                .issuedAt(createdDate)
                .expiresAt(expirationDate)
                .build();
    }


}

