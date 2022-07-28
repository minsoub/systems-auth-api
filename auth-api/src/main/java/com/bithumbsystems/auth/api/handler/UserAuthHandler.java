package com.bithumbsystems.auth.api.handler;

import com.bithumbsystems.auth.core.model.request.UserCaptchaRequest;
import com.bithumbsystems.auth.core.model.request.UserJoinRequest;
import com.bithumbsystems.auth.core.model.request.UserRequest;
import com.bithumbsystems.auth.core.model.request.token.AuthRequest;
import com.bithumbsystems.auth.core.model.response.SingleResponse;
import com.bithumbsystems.auth.core.model.response.token.TokenResponse;
import com.bithumbsystems.auth.service.user.UserService;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Component;
import org.springframework.web.reactive.function.server.ServerRequest;
import org.springframework.web.reactive.function.server.ServerResponse;
import reactor.core.publisher.Mono;

/**
 * The type Auth handler.
 */
@Slf4j
@Component
@RequiredArgsConstructor
public class UserAuthHandler {

  private final UserService userService;

  /**
   * Refresh token mono.
   *
   * @param request the request
   * @return the mono
   */
  public Mono<ServerResponse> refreshToken(ServerRequest request) {
    Mono<AuthRequest> authRequest = request.bodyToMono(AuthRequest.class);
    return ServerResponse.ok().body(userService.reGenerateToken(authRequest), TokenResponse.class);
  }


  /**
   * 일반 사용자 로그인 인증 처리
   *
   * @param request the request
   * @return mono mono
   */
  public Mono<ServerResponse> userLogin(ServerRequest request) {
    Mono<UserRequest> userRequest = request.bodyToMono(UserRequest.class);

    return ServerResponse.ok().body(userService.userLogin(userRequest), TokenResponse.class);
  }

  /**
   * 일반 사용자 로그인 인증 처리 with captcha
   *
   * @param request the request
   * @return mono mono
   */
  public Mono<ServerResponse> userCaptchaLogin(ServerRequest request) {
    Mono<UserCaptchaRequest> userCaptchaRequest = request.bodyToMono(UserCaptchaRequest.class);

    return ServerResponse.ok()
        .body(userService.userCaptchaLogin(userCaptchaRequest), TokenResponse.class);
  }

  /**
   * 사용자 가입을 처리한다.
   *
   * @param request the request
   * @return mono mono
   */
  public Mono<ServerResponse> userJoin(ServerRequest request) {
    Mono<UserJoinRequest> joinRequest = request.bodyToMono(UserJoinRequest.class);

    return ServerResponse.ok().body(userService.join(joinRequest), SingleResponse.class);
  }
}
