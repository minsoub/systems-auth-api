package com.bithumbsystems.auth.service.lrc;

import com.bithumbsystems.auth.api.config.AwsConfig;
import com.bithumbsystems.auth.api.config.constant.SecurityConstant;
import com.bithumbsystems.auth.api.config.properties.JwtProperties;
import com.bithumbsystems.auth.api.exception.authorization.UnauthorizedException;
import com.bithumbsystems.auth.core.model.request.OtpRequest;
import com.bithumbsystems.auth.core.model.request.token.TokenGenerateRequest;
import com.bithumbsystems.auth.core.model.response.token.TokenResponse;
import com.bithumbsystems.auth.core.util.AES256Util;
import com.bithumbsystems.auth.core.util.JwtVerifyUtil;
import com.bithumbsystems.auth.core.util.OtpUtil;
import com.bithumbsystems.auth.data.mongodb.client.service.LrcAccountDomainService;
import com.bithumbsystems.auth.data.redis.entity.OtpHistory;
import com.bithumbsystems.auth.data.redis.service.OtpHistoryDomainService;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Service;
import reactor.core.publisher.Mono;
import reactor.core.scheduler.Schedulers;

import java.time.LocalDateTime;
import java.util.Map;
import java.util.Optional;

import static com.bithumbsystems.auth.core.model.enums.ErrorCode.INVALID_OTP_NUMBER;

/**
 * The type Otp service.
 */
@Service
@Slf4j
@RequiredArgsConstructor
public class LrcOtpService {

  private final JwtProperties jwtProperties;
  private final OtpHistoryDomainService otpHistoryDomainService;
  private final AwsConfig config;
  private final LrcTokenService userTokenService;
  private final LrcAccountDomainService userAccountDomainService;
  /**
   * OTP 처리 - 2차 처리완료 후 토큰정보를 리턴한다.
   *
   * @param request the request
   * @return mono mono
   */
  public Mono<TokenResponse> otpValidation(OtpRequest request) {
    // Token Validation check and otp no check
    log.debug("otp validation check start => {}", request);

    String encodeKey = AES256Util.decryptAES(config.getCryptoKey(), request.getCheckData());

    return
        checkExpiredOTP(request, encodeKey)
            .then(

                JwtVerifyUtil.check(request.getToken(), jwtProperties.getSecret())
                    .flatMap(result -> {
                      // success token validation check
                      // otp validation check
                      log.debug("jwt validation check completed : {}", result);
                      if (OtpUtil.otpCheckCode(request.getOtpNo(), encodeKey)) {
                        // 2차 토큰 생성
                        log.debug("2차 토큰 생성");
                          String accountId = result.claims.get("account_id").toString();
                          return userAccountDomainService.findById(accountId).flatMap(userAccount -> {
                              return userTokenService.generateToken(TokenGenerateRequest.builder()
                                              .accountId(userAccount.getId())
                                              .roles("USER")
                                              .siteId(SecurityConstant.LRC_SITE_ID)
                                              .email(AES256Util.decryptAES(config.getKmsKey(), userAccount.getEmail()))
                                              .claims(Map.of("ROLE", "USER", "account_id", userAccount.getId()))
                                              .build())
                                      .publishOn(Schedulers.boundedElastic())
                                      .map(tokenResponse -> {
                                          log.debug("generateToken => {}", tokenResponse);
                                          userAccount.setLastLoginDate(LocalDateTime.now());
                                          userAccount.setLoginFailCount(0);   // 로그인 성공시 로그인 실패횟수 초기화
                                          userAccount.setLoginFailDate(null); // 로그인 성공시 로그인 실패시간 초기화
                                          userAccountDomainService.save(userAccount).then().log("result completed...")
                                                  .subscribe();
                                          tokenResponse.setEmail(AES256Util.encryptAES(config.getLrcCryptoKey(), tokenResponse.getEmail()));
                                          return tokenResponse;
                                      });
                          });
                      } else {
                        log.debug("OTP check error");
                        return Mono.error(new UnauthorizedException(INVALID_OTP_NUMBER));
                      }
                    })
            );
  }

  private Mono<Void> checkExpiredOTP(OtpRequest request, String encodeKey) {
    Optional<OtpHistory> otpHistoryOptional = otpHistoryDomainService.searchOtpHistory(
        request.getSiteId() + ":" + encodeKey + ":" + request.getOtpNo());

    // 1번 사용했던 OTP 번호 재시도 시 오류 처리(보안취약점 - 자동화공격 방지)
    if (otpHistoryOptional.isPresent()) {
      return Mono.error(new UnauthorizedException(INVALID_OTP_NUMBER));
    }
    return Mono.empty();
  }
}
