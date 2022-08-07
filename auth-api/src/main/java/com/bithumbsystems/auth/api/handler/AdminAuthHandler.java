package com.bithumbsystems.auth.api.handler;

import com.bithumbsystems.auth.core.model.auth.TokenInfo;
import com.bithumbsystems.auth.core.model.auth.TokenOtpInfo;
import com.bithumbsystems.auth.core.model.request.AdminRequest;
import com.bithumbsystems.auth.core.model.request.OtpClearRequest;
import com.bithumbsystems.auth.core.model.request.OtpRequest;
import com.bithumbsystems.auth.core.model.request.UserRequest;
import com.bithumbsystems.auth.core.model.request.token.AuthRequest;
import com.bithumbsystems.auth.core.model.response.SingleResponse;
import com.bithumbsystems.auth.core.model.response.token.TokenResponse;
import com.bithumbsystems.auth.data.mongodb.client.entity.AdminAccount;
import com.bithumbsystems.auth.service.admin.AdminAccountService;
import com.bithumbsystems.auth.service.admin.AdminTokenService;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Component;
import org.springframework.web.reactive.function.server.ServerRequest;
import org.springframework.web.reactive.function.server.ServerResponse;
import reactor.core.publisher.Mono;

/**
 * The type Admin auth handler.
 */
@Slf4j
@Component
@RequiredArgsConstructor
public class AdminAuthHandler {
  private final AdminAccountService adminAccountService;

  private final AdminTokenService adminTokenService;

  /**
   * Refresh token mono.
   *
   * @param request the request
   * @return the mono
   */
  public Mono<ServerResponse> refreshToken(ServerRequest request) {
    Mono<AuthRequest> authRequest = request.bodyToMono(AuthRequest.class);
    return ServerResponse.ok().body(adminTokenService.reGenerateToken(authRequest), TokenResponse.class);
  }

  /**
   * 사용자 로그인 처리 (운영자) 사용자 로그인 후 OTP 처리를 해야 한다.
   *
   * @param request the request
   * @return mono mono
   */
  public Mono<ServerResponse> login(ServerRequest request) {
    log.debug("login called..");
    Mono<UserRequest> userRequest = request.bodyToMono(UserRequest.class);

    return ServerResponse.ok().body(adminAccountService.login(userRequest), TokenOtpInfo.class);
  }

  /**
   * QR 바코드를 생성해서 리턴한다.
   *
   * @param request the request
   * @return mono mono
   */
  public Mono<ServerResponse> otp(ServerRequest request) {
    Mono<OtpRequest> otpRequest = request.bodyToMono(OtpRequest.class);

    return ServerResponse.ok().body(adminAccountService.otp(otpRequest), TokenInfo.class);
  }

  /**
   * 사용자 패스워드 업데이트 및 상태 업데이트
   *
   * @param request the request
   * @return mono mono
   */
  public Mono<ServerResponse> passwordUpdate(ServerRequest request) {
    log.debug("login called..");
    Mono<UserRequest> userRequest = request.bodyToMono(UserRequest.class);

    return ServerResponse.ok().body(adminAccountService.passwordUpdate(userRequest), SingleResponse.class);
  }

  /**
   * OTP Key 정보를 Clear 한다.
   *
   * @param request the request
   * @return mono mono
   */
  public Mono<ServerResponse> otpClear(ServerRequest request) {
    Mono<OtpClearRequest> otpClearRequestMono = request.bodyToMono(OtpClearRequest.class);

    return ServerResponse.ok().body(adminAccountService.otpClear(otpClearRequestMono), AdminAccount.class);
  }

  /**
   * Send temp password mail mono.
   *
   * @param request the request
   * @return the mono
   */
  public Mono<ServerResponse> sendTempPasswordMail(ServerRequest request) {
    Mono<AdminRequest> adminRequestMono = request.bodyToMono(AdminRequest.class);

    return ServerResponse.ok().body(adminAccountService.sendTempPasswordMail(adminRequestMono), AdminAccount.class);
  }
}
