package com.bithumbsystems.auth.api.handler;

import com.bithumbsystems.auth.core.model.request.TokenValidationRequest;
import com.bithumbsystems.auth.service.AuthService;
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

}
