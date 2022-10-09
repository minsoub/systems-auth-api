package com.bithumbsystems.auth.api.handler;

import com.bithumbsystems.auth.core.model.request.TokenValidationRequest;
import com.bithumbsystems.auth.core.model.response.PublicKeyResponse;
import com.bithumbsystems.auth.service.AuthService;
import java.nio.charset.StandardCharsets;
import java.util.Base64;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Component;
import org.springframework.web.reactive.function.server.ServerRequest;
import org.springframework.web.reactive.function.server.ServerResponse;
import reactor.core.publisher.Mono;

@Component
@Slf4j
@RequiredArgsConstructor
public class AuthHandler {
  private final AuthService authService;


  /**
   * Token Validation을 체크한다.
   *
   * @param request the request
   * @return mono mono
   */
  public Mono<ServerResponse> authorize(ServerRequest request) {
    Mono<TokenValidationRequest> tokenRequest = request.bodyToMono(TokenValidationRequest.class);
    return ServerResponse.ok().body(authService.authorize(tokenRequest), String.class);
  }

  /**
   * RSA Public Key를 리턴한다.
   *
   * @param request
   * @return
   */
  public Mono<ServerResponse> publicKey(ServerRequest request) {
    return authService.getRsaPublicKey()
        .map(pubKey -> PublicKeyResponse.builder()
            .publicKey(Base64.getEncoder().encodeToString(pubKey.getBytes(StandardCharsets.UTF_8)))
            .build())
        .flatMap(res -> ServerResponse.ok().bodyValue(res));
  }

  public Mono<ServerResponse> redisInit(ServerRequest serverRequest) {
    return ServerResponse.ok().bodyValue(authService.redisInit());
  }
}
