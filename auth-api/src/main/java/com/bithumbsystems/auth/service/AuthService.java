package com.bithumbsystems.auth.service;

import com.bithumbsystems.auth.api.config.property.JwtProperties;
import com.bithumbsystems.auth.api.exception.authorization.DuplicatedLoginException;
import com.bithumbsystems.auth.core.model.auth.VerificationResult;
import com.bithumbsystems.auth.core.model.enums.ErrorCode;
import com.bithumbsystems.auth.core.model.enums.ResultCode;
import com.bithumbsystems.auth.core.model.request.TokenValidationRequest;
import com.bithumbsystems.auth.core.util.JwtVerifyUtil;
import com.bithumbsystems.auth.data.redis.RedisTemplateSample;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Service;
import reactor.core.publisher.Mono;

/**
 * The type Auth service.
 */
@Service
@Slf4j
@RequiredArgsConstructor
public class AuthService {

  private final JwtProperties jwtProperties;

  private final RedisTemplateSample redisTemplate;

  /**
   * Authorize
   *
   * @param tokenRequest the token request
   * @return the mono
   */
  public Mono<String> authorize(Mono<TokenValidationRequest> tokenRequest) {
    return tokenRequest
        .flatMap(this::tokenValidate)
        .flatMap(verificationResult -> {
          var key = verificationResult.claims.getIssuer();
          if (verificationResult.claims.get("ROLE").equals("USER")) {
            key += "::LRC";
          }
          return redisTemplate.getToken(key)
              .filter(token -> token.equals(verificationResult.token))
              .map(token -> {
                log.debug("authorize : {}", token);
                return ResultCode.SUCCESS.name();
              }).switchIfEmpty(Mono.error(new DuplicatedLoginException(ErrorCode.USER_ALREADY_LOGIN)));
        });
  }

  /**
   * Token Validation 을 체크한다.
   *
   * @param tokenValidationRequest the token validation request
   * @return mono mono
   */
  private Mono<VerificationResult> tokenValidate(TokenValidationRequest tokenValidationRequest) {
    return JwtVerifyUtil.check(tokenValidationRequest.getToken(), jwtProperties.getSecret());
  }
}
