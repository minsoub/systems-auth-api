package com.bithumbsystems.auth.api.handler;

import com.bithumbsystems.auth.api.config.AwsConfig;
import com.bithumbsystems.auth.api.config.constant.SecurityConstant;
import com.bithumbsystems.auth.api.exception.authorization.UnauthorizedException;
import com.bithumbsystems.auth.core.model.auth.TokenInfo;
import com.bithumbsystems.auth.core.model.auth.TokenOtpInfo;
import com.bithumbsystems.auth.core.model.enums.ErrorCode;
import com.bithumbsystems.auth.core.model.request.*;
import com.bithumbsystems.auth.core.model.request.token.AuthRequest;
import com.bithumbsystems.auth.core.model.response.KeyResponse;
import com.bithumbsystems.auth.core.model.response.SingleResponse;
import com.bithumbsystems.auth.core.model.response.token.TokenResponse;
import com.bithumbsystems.auth.service.admin.AdminAccountService;
import com.bithumbsystems.auth.service.admin.AdminTokenService;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Component;
import org.springframework.web.reactive.function.server.ServerRequest;
import org.springframework.web.reactive.function.server.ServerResponse;
import reactor.core.publisher.Mono;

import java.nio.charset.StandardCharsets;
import java.util.Base64;

/**
 * The type Admin auth handler.
 */
@Slf4j
@Component
@RequiredArgsConstructor
public class AdminAuthHandler {
  private final AdminAccountService adminAccountService;

  private final AdminTokenService adminTokenService;

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

    return ServerResponse.ok().body(adminAccountService.otpClear(otpClearRequestMono), SingleResponse.class);
  }
  /**
   * Send temp password mail mono.
   * 임시 패스워드 요청으로 인한 Confirm 메일을 전송한다.
   *
   * @param request the request
   * @return the mono
   */
  public Mono<ServerResponse> sendTempPasswordInit(ServerRequest request) {
    Mono<AdminRequest> adminRequestMono = request.bodyToMono(AdminRequest.class);

    return ServerResponse.ok().body(adminAccountService.sendTempPasswordInit(adminRequestMono), SingleResponse.class);
  }
  /**
   * Send temp password mail mono.
   * 임시 패스워드 요청으로 인한 Confirm 메일을 전송한다.
   *
   * @param request the request
   * @return the mono
   */
  public Mono<ServerResponse> sendTempPasswordMail(ServerRequest request) {
    Mono<AdminTempRequest> adminRequestMono = request.bodyToMono(AdminTempRequest.class);

    return ServerResponse.ok().body(adminAccountService.sendTempPasswordMail(adminRequestMono), SingleResponse.class);
  }
}
