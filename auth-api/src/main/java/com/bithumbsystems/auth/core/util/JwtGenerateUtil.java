package com.bithumbsystems.auth.core.util;

import com.bithumbsystems.auth.core.model.auth.GenerateTokenInfo;
import com.bithumbsystems.auth.core.model.auth.TokenInfo;
import com.bithumbsystems.auth.core.model.auth.TokenOtpInfo;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.security.Keys;
import java.util.Date;
import java.util.UUID;

public class JwtGenerateUtil {

  public static TokenInfo generate(GenerateTokenInfo generateTokenInfo) {
    Date expirationDate = getExpirationDate(generateTokenInfo);
    Date refreshExpirationDate = getRefreshExpirationDate(generateTokenInfo);

    var createdDate = new Date();
    var token = makeToken(generateTokenInfo, expirationDate, createdDate); // access token

    // refreshToken
    var refreshToken = Jwts.builder()
        .setClaims(generateTokenInfo.getClaims())
        .setIssuer(generateTokenInfo.getIssuer())
        .setSubject(generateTokenInfo.getSubject())
        .setIssuedAt(createdDate)
        .setId(UUID.randomUUID().toString())
        .setExpiration(refreshExpirationDate)
        .signWith(Keys.hmacShaKeyFor(generateTokenInfo.getSecret().getBytes()))
        .compact();

    return TokenInfo.builder()
        .accessToken(token)
        .refreshToken(refreshToken)
        .issuedAt(createdDate)
        .expiresAt(expirationDate)
        .build();
  }

  public static TokenOtpInfo generateOtp(GenerateTokenInfo generateTokenInfo) {
    Date expirationDate = getExpirationDate(generateTokenInfo);

    var createdDate = new Date();
    var token = makeToken(generateTokenInfo, expirationDate, createdDate);

    return TokenOtpInfo.builder()
        .token(token)
        .issuedAt(createdDate)
        .expiresAt(expirationDate)
        .build();
  }

  private static String makeToken(GenerateTokenInfo generateTokenInfo, Date expirationDate,
      Date createdDate) {
    return Jwts.builder()
        .setClaims(generateTokenInfo.getClaims())
        .setIssuer(generateTokenInfo.getIssuer())
        .setSubject(generateTokenInfo.getSubject())
        .setIssuedAt(createdDate)
        .setId(UUID.randomUUID().toString())
        .setExpiration(expirationDate)
        .signWith(Keys.hmacShaKeyFor(generateTokenInfo.getSecret().getBytes()))
        .compact();
  }

  private static Date getExpirationDate(GenerateTokenInfo generateTokenInfo) {
    var expirationTimeInMilliseconds = Long.parseLong(generateTokenInfo.getExpiration()) * 1000;
    return new Date(System.currentTimeMillis() + expirationTimeInMilliseconds);
  }

  private static Date getRefreshExpirationDate(GenerateTokenInfo generateTokenInfo) {
    var expirationTimeInMilliseconds =
        Long.parseLong(generateTokenInfo.getRefreshExpiration()) * 1000;
    return new Date(System.currentTimeMillis() + expirationTimeInMilliseconds);
  }
}

