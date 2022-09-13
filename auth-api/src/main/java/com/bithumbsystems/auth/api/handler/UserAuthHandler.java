package com.bithumbsystems.auth.api.handler;

import com.bithumbsystems.auth.api.config.AwsConfig;
import com.bithumbsystems.auth.api.config.constant.SecurityConstant;
import com.bithumbsystems.auth.api.exception.authorization.UnauthorizedException;
import com.bithumbsystems.auth.core.model.enums.ErrorCode;
import com.bithumbsystems.auth.core.model.request.UserCaptchaRequest;
import com.bithumbsystems.auth.core.model.request.UserJoinRequest;
import com.bithumbsystems.auth.core.model.request.UserRequest;
import com.bithumbsystems.auth.core.model.request.token.AuthRequest;
import com.bithumbsystems.auth.core.model.response.KeyResponse;
import com.bithumbsystems.auth.core.model.response.SingleResponse;
import com.bithumbsystems.auth.core.model.response.token.TokenResponse;
import com.bithumbsystems.auth.service.user.UserService;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Component;
import org.springframework.web.reactive.function.server.ServerRequest;
import org.springframework.web.reactive.function.server.ServerResponse;
import reactor.core.publisher.Mono;

import java.nio.charset.StandardCharsets;
import java.util.Base64;

/**
 * The type Auth handler.
 */
@Slf4j
@Component
@RequiredArgsConstructor
public class UserAuthHandler {

  private final UserService userService;

  private final AwsConfig config;

  /**
   * Crypto Key를 리턴한다.
   *
   * @param request
   * @return
   */
  public Mono<ServerResponse> initKey(ServerRequest request) {
    String siteId = null;
    String cryptoKey = null;
    if (!request.exchange().getRequest().getHeaders().containsKey(SecurityConstant.SITE_ID)) {
      log.debug(">>>>> SITE ID NOT CONTAINS <<<<<");
      log.debug(">>>>>HEADER => {}", request.exchange().getRequest().getHeaders());
      log.debug(">>>>>URI => {}", request.exchange().getRequest().getURI());

      throw new UnauthorizedException(ErrorCode.INVALID_HEADER_SITE_ID);
    } else {
      siteId = request.exchange().getRequest().getHeaders().getFirst(SecurityConstant.SITE_ID);
    }

    // LRC/CPC/SMART-ADMIN
    if (siteId.equals(SecurityConstant.CPC_SITE_ID)) {
      cryptoKey = config.getCpcCryptoKey();
    } else if(siteId.equals(SecurityConstant.LRC_SITE_ID)) {
      cryptoKey = config.getLrcCryptoKey();
    } else if(siteId.equals(SecurityConstant.MNG_SITE_ID)) {
      cryptoKey = config.getCryptoKey();
    }

    KeyResponse res = KeyResponse.builder()
            .initData(Base64.getEncoder().encodeToString(cryptoKey.getBytes(StandardCharsets.UTF_8)))
            .build();

    return ServerResponse.ok().bodyValue(res);
  }
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
