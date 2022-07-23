package com.bithumbsystems.auth.api.handler;

import com.bithumbsystems.auth.core.model.auth.TokenInfo;
import com.bithumbsystems.auth.core.model.request.UserCaptchaRequest;
import com.bithumbsystems.auth.core.model.request.UserJoinRequest;
import com.bithumbsystems.auth.core.model.request.UserRequest;
import com.bithumbsystems.auth.core.model.response.SingleResponse;
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
   * 일반 사용자 로그인 인증 처리
   *
   * @param request the request
   * @return mono mono
   */
  public Mono<ServerResponse> userLogin(ServerRequest request) {
    Mono<UserRequest> userRequest = request.bodyToMono(UserRequest.class);

    return ServerResponse.ok().body(userService.userLogin(userRequest), TokenInfo.class);
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
        .body(userService.userCaptchaLogin(userCaptchaRequest), TokenInfo.class);
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
