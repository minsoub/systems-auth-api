package com.bithumbsystems.auth.service;

import com.bithumbsystems.auth.api.config.properties.JwtProperties;
import com.bithumbsystems.auth.api.exception.authorization.DuplicatedLoginException;
import com.bithumbsystems.auth.core.model.auth.VerificationResult;
import com.bithumbsystems.auth.core.model.enums.ErrorCode;
import com.bithumbsystems.auth.core.model.enums.ResultCode;
import com.bithumbsystems.auth.core.model.request.TokenValidationRequest;
import com.bithumbsystems.auth.core.util.JwtVerifyUtil;
import com.bithumbsystems.auth.data.mongodb.client.service.RsaCipherInfoDomainService;
import com.bithumbsystems.auth.data.redis.RedisTemplateSample;
import com.bithumbsystems.auth.data.mongodb.client.entity.RsaCipherInfo;
import com.bithumbsystems.auth.service.cipher.RsaCipherService;
import java.time.LocalDateTime;
import java.util.Map;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;
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

  private final RsaCipherInfoDomainService rsaCipherInfoDomainService;

  private final RsaCipherService rsaCipherService;
  private static String RSA_CIPHER_KEY = "rsa-cipher-key";

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

  @Transactional
  public Mono<RsaCipherInfo> createRsaCipherCache() {
    Map<String, String> serverRsaKeys = rsaCipherService.getRsaKeys();
    log.info("serverRsaKeys : {}", serverRsaKeys);

    return rsaCipherInfoDomainService.save(RsaCipherInfo.builder()
        .id(RSA_CIPHER_KEY)
        .serverPrivateKey(serverRsaKeys.get(rsaCipherService.PRIVATE_KEY_NAME))
        .serverPublicKey(serverRsaKeys.get(rsaCipherService.PUBLIC_KEY_NAME))
        .createdAt(LocalDateTime.now())
        .build());
  }

  public Mono<String> getRsaPublicKey() {
    return rsaCipherInfoDomainService.findById(RSA_CIPHER_KEY)
        .map(RsaCipherInfo::getServerPublicKey);
  }

  public Mono<String> getRsaPrivateKey() {
    return rsaCipherInfoDomainService.findById(RSA_CIPHER_KEY)
        .map(RsaCipherInfo::getServerPrivateKey);
  }
}
