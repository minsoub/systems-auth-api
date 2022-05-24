package com.bithumbsystems.auth.core.util;

import com.bithumbsystems.auth.core.model.auth.GenerateTokenInfo;
import com.bithumbsystems.auth.core.model.auth.TokenInfo;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.security.Keys;
import java.util.Date;
import java.util.UUID;

public final class JwtGenerateUtil {

    public static TokenInfo generate(GenerateTokenInfo generateTokenInfo) {
        var expirationTimeInMilliseconds = Long.parseLong(generateTokenInfo.getExpiration()) * 1000;
        var expirationDate = new Date(new Date().getTime() + expirationTimeInMilliseconds);

        var createdDate = new Date();
        var token = Jwts.builder()
                .setClaims(generateTokenInfo.getClaims())
                .setIssuer(generateTokenInfo.getIssuer())
                .setSubject(generateTokenInfo.getSubject())
                .setIssuedAt(createdDate)
                .setId(UUID.randomUUID().toString())
                .setExpiration(expirationDate)
                .signWith(Keys.hmacShaKeyFor(generateTokenInfo.getSecret().getBytes()))
                .compact();

        return TokenInfo.builder()
                .token(token)
                .issuedAt(createdDate)
                .expiresAt(expirationDate)
                .build();
    }


}

