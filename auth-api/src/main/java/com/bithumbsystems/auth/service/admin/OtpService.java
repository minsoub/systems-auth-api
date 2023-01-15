package com.bithumbsystems.auth.service.admin;

import static com.bithumbsystems.auth.core.model.enums.ErrorCode.INVALID_OTP_NUMBER;

import com.bithumbsystems.auth.api.config.AwsConfig;
import com.bithumbsystems.auth.api.config.properties.JwtProperties;
import com.bithumbsystems.auth.api.exception.authorization.UnauthorizedException;
import com.bithumbsystems.auth.core.model.auth.TokenInfo;
import com.bithumbsystems.auth.core.model.request.OtpRequest;
import com.bithumbsystems.auth.core.model.request.token.TokenGenerateRequest;
import com.bithumbsystems.auth.core.util.AES256Util;
import com.bithumbsystems.auth.core.util.JwtVerifyUtil;
import com.bithumbsystems.auth.core.util.OtpUtil;
import com.bithumbsystems.auth.data.authentication.enums.Status;
import com.bithumbsystems.auth.data.authentication.service.AdminAccountDomainService;
import com.bithumbsystems.auth.data.redis.entity.OtpCheck;
import com.bithumbsystems.auth.data.redis.entity.OtpHistory;
import com.bithumbsystems.auth.data.redis.service.OtpCheckDomainService;
import com.bithumbsystems.auth.data.redis.service.OtpHistoryDomainService;
import java.time.LocalDateTime;
import java.util.Optional;
import java.util.concurrent.atomic.AtomicInteger;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Service;
import reactor.core.publisher.Mono;
import reactor.core.scheduler.Schedulers;

/**
 * The type Otp service.
 */
@Service
@Slf4j
@RequiredArgsConstructor
public class OtpService {

  private final JwtProperties jwtProperties;
  private final AdminTokenService adminTokenService;
  private final AdminAccountDomainService adminAccountDomainService;
  private final OtpHistoryDomainService otpHistoryDomainService;
  private final OtpCheckDomainService otpCheckDomainService;

  private final AwsConfig config;

  /**
   * OTP 처리 - 2차 처리완료 후 토큰정보를 리턴한다.
   *
   * @param request the request
   * @return mono mono
   */
  public Mono<TokenInfo> otpValidation(OtpRequest request) {
    // Token Validation check and otp no check
    log.debug("otp validation check start => {}", request);

    String encodeKey = AES256Util.decryptAES(config.getCryptoKey(), request.getCheckData());

    return
        checkExpiredOTP(request, encodeKey)
            .then(
                JwtVerifyUtil.check(request.getToken(), jwtProperties.getSecret())
                    .publishOn(Schedulers.boundedElastic())
                    .flatMap(result -> {
                      // success token validation check
                      // otp validation check
                      log.debug("jwt validation check completed : {}", result);
                      if (OtpUtil.otpCheckCode(request.getOtpNo(), encodeKey)) {
                        // 2차 토큰 생성
                        log.debug("2차 토큰 생성");

                        return adminTokenService.generateToken(
                            TokenGenerateRequest.builder()
                                .accountId(result.claims.get("account_id").toString())
                                .roles(result.claims.get("ROLE"))
                                .siteId(request.getSiteId())
                                .status(request.getStatus())
                                .email(result.claims.getIssuer())
                                .name(request.getName())
                                .build()
                        ).publishOn(Schedulers.boundedElastic()).doOnSuccess(n -> {
                          // OTP 조회 이력 Redis에 저장
                          otpHistoryDomainService.save(OtpHistory.builder()
                              .id(request.getSiteId() + ":" + encodeKey + ":" + request.getOtpNo())
                              .build());
                          otpCheckDomainService.save(OtpCheck.builder()
                              .id("OTP_CHECK::" + result.claims.get("account_id").toString())
                              .failCount("0").build()).subscribe();
                          // 사용자 encodeKey 저장.
                          adminAccountDomainService.findById(
                                  result.claims.get("account_id").toString())
                              .publishOn(Schedulers.boundedElastic())
                              .map(account -> {
                                account.setOtpSecretKey(encodeKey); // request.getEncodeKey());
                                account.setLastLoginDate(LocalDateTime.now());
                                account.setLoginFailCount(0L);
                                if (!OtpUtil.needPasswordChange(account)) {
                                  account.setStatus(Status.NORMAL);
                                }
                                adminAccountDomainService.save(account).then()
                                    .log("save otp key info")
                                    .subscribe();
                                return account;
                              }).subscribe();
                        }).flatMap(Mono::just);
                      } else {
                        otpFailCheck(result.claims.get("account_id").toString());

                        log.debug("OTP check error");
                        return Mono.error(new UnauthorizedException(INVALID_OTP_NUMBER));
                      }
                    })
            );
  }

  private void otpFailCheck(String accountId) {
    String otpCheckId = "OTP_CHECK::" + accountId;
    otpCheckDomainService.findById(otpCheckId)
        .switchIfEmpty(Mono.just("0"))
        .publishOn(Schedulers.boundedElastic())
        .map(failCount -> {
          AtomicInteger fail = new AtomicInteger(Integer.parseInt(failCount));
          return adminAccountDomainService.findById(accountId)
              .publishOn(Schedulers.boundedElastic())
              .flatMap(adminAccount -> {
                if(adminAccount.getStatus().equals(Status.INIT_OTP_REQUEST)){
                  fail.set(0);
                } else if(fail.get() > 4){
                  adminAccount.setStatus(Status.INIT_OTP_REQUEST);
                  adminAccount.setOtpSecretKey(null);
                } else {
                  fail.incrementAndGet();
                }
                log.info("fail:" + fail);
                adminAccountDomainService.save(adminAccount).subscribe();
                return Mono.empty();
              }).flatMap( account ->
                  otpCheckDomainService.save(OtpCheck.builder()
                    .id(otpCheckId)
                    .failCount(String.valueOf(fail)).build())
              ).subscribe();
        }).subscribe();
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
