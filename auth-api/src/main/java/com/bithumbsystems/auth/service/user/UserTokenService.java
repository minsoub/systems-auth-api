package com.bithumbsystems.auth.service.user;

import static com.bithumbsystems.auth.core.model.enums.ErrorCode.INVALID_TOKEN;

import com.bithumbsystems.auth.api.config.property.JwtProperties;
import com.bithumbsystems.auth.api.exception.authorization.UnauthorizedException;
import com.bithumbsystems.auth.core.model.auth.GenerateTokenInfo;
import com.bithumbsystems.auth.core.model.enums.TokenType;
import com.bithumbsystems.auth.core.model.request.token.AuthRequest;
import com.bithumbsystems.auth.core.model.request.token.TokenGenerateRequest;
import com.bithumbsystems.auth.core.model.response.token.TokenResponse;
import com.bithumbsystems.auth.core.util.JwtGenerateUtil;
import com.bithumbsystems.auth.core.util.JwtVerifyUtil;
import com.bithumbsystems.auth.data.redis.RedisTemplateSample;
import com.bithumbsystems.auth.service.TokenService;
import java.util.Map;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Service;
import reactor.core.publisher.Mono;

@Slf4j
@Service
@RequiredArgsConstructor
public class UserTokenService implements TokenService {

  private final JwtProperties jwtProperties;
  private final RedisTemplateSample redisTemplateSample;

  /**
   * refresh 토큰으로 갱신
   *
   * @param authRequest the auth request
   * @return mono
   */
  public Mono<TokenResponse> reGenerateToken(Mono<AuthRequest> authRequest) {
    return authRequest.flatMap(tokenInfo -> {
      log.debug("reGenerateToken data => {}", authRequest);

      return JwtVerifyUtil.check(tokenInfo.getRefreshToken(), jwtProperties.getSecret())
          .flatMap(verificationResult -> redisTemplateSample.getToken((String) verificationResult.claims.get("iss"))
              .filter(token -> token.equals(tokenInfo.getAccessToken()))
              .switchIfEmpty(Mono.error(new UnauthorizedException(INVALID_TOKEN)))
              .then(generateToken(TokenGenerateRequest.builder()
                  .accountId(verificationResult.claims.get("account_id").toString())
                  .roles(verificationResult.claims.get("ROLE"))
                  .siteId(verificationResult.claims.get("sub").toString())
                  .claims(Map.of("ROLE", "USER", "account_id", verificationResult.claims.get("account_id").toString()))
                  .email(verificationResult.claims.getIssuer())
                  .build())
              ));
    });
  }


  public Mono<TokenResponse> generateToken(TokenGenerateRequest request) {
    log.debug("generateToken create......{}", request);

    GenerateTokenInfo generateTokenInfo = GenerateTokenInfo
        .builder()
        .secret(jwtProperties.getSecret())
        .expiration(jwtProperties.getExpiration().get(TokenType.ACCESS.getValue()))
        .refreshExpiration(jwtProperties.getExpiration().get(TokenType.REFRESH.getValue()))
        .subject(request.getSiteId())
        .issuer(request.getEmail())
        .claims(request.getClaims())
        .build();
    var tokenInfo = JwtGenerateUtil.generate(generateTokenInfo)
        .toBuilder()
        .build();

    var tokenResponse = TokenResponse.builder()
        .id(request.getAccountId())
        .accessToken(tokenInfo.getAccessToken())
        .accessExpiresAt(tokenInfo.getExpiresAt())
        .refreshToken(tokenInfo.getRefreshToken())
        .refreshExpiresAt(tokenInfo.getRefreshExpiresAt())
        .issuedAt(tokenInfo.getIssuedAt())
        .email(request.getEmail())
        .build();

    log.debug("tokenResponse info => {}", tokenResponse);
    return redisTemplateSample.saveToken(request.getEmail() + "::USER", tokenInfo.getAccessToken())
        .map(result -> tokenResponse);
  }
}
