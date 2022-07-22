package com.bithumbsystems.auth.service;

import com.bithumbsystems.auth.api.config.property.JwtProperties;
import com.bithumbsystems.auth.core.model.request.TokenValidationRequest;
import com.bithumbsystems.auth.core.util.JwtVerifyUtil;
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


  /**
   * Token Validation 을 체크한다.
   *
   * @param tokenValidationRequestMono the token validation request mono
   * @return mono
   */
  public Mono<String> tokenValidate(Mono<TokenValidationRequest> tokenValidationRequestMono) {
    return tokenValidationRequestMono
        .flatMap(res -> JwtVerifyUtil.check(res.getToken(), jwtProperties.getSecret())
            .map(result -> "Success"));
  }
}
