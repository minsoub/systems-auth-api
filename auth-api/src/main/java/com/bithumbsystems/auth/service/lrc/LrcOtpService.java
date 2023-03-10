package com.bithumbsystems.auth.service.lrc;

import static com.bithumbsystems.auth.core.model.enums.ErrorCode.INVALID_OTP_NUMBER;

import com.bithumbsystems.auth.api.config.AwsConfig;
import com.bithumbsystems.auth.api.config.constant.SecurityConstant;
import com.bithumbsystems.auth.api.config.properties.JwtProperties;
import com.bithumbsystems.auth.api.exception.authorization.LrcUnauthorizedException;
import com.bithumbsystems.auth.api.exception.authorization.UnauthorizedException;
import com.bithumbsystems.auth.core.model.request.OtpRequest;
import com.bithumbsystems.auth.core.model.request.token.TokenGenerateRequest;
import com.bithumbsystems.auth.core.model.response.OtpResponse;
import com.bithumbsystems.auth.core.model.response.token.TokenResponse;
import com.bithumbsystems.auth.core.util.AES256Util;
import com.bithumbsystems.auth.core.util.JwtVerifyUtil;
import com.bithumbsystems.auth.core.util.OtpUtil;
import com.bithumbsystems.auth.data.authentication.entity.LrcAccount;
import com.bithumbsystems.auth.data.authentication.service.LrcAccountDomainService;
import com.bithumbsystems.auth.data.redis.entity.OtpHistory;
import com.bithumbsystems.auth.data.redis.service.OtpHistoryDomainService;
import com.bithumbsystems.auth.model.lrc.CheckResultResponse;
import com.bithumbsystems.auth.model.lrc.EmailValidKey;
import com.bithumbsystems.auth.model.lrc.LrcOtpRequest;
import com.bithumbsystems.auth.model.lrc.LrcResetRequest;
import com.bithumbsystems.auth.model.lrc.ResetInfoResponse;
import com.bithumbsystems.auth.model.lrc.enums.ErrorCode;
import java.nio.charset.StandardCharsets;
import java.time.LocalDateTime;
import java.util.Map;
import java.util.Optional;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.apache.commons.codec.binary.Base64;
import org.joda.time.DateTime;
import org.joda.time.Duration;
import org.joda.time.format.DateTimeFormat;
import org.joda.time.format.DateTimeFormatter;
import org.springframework.stereotype.Service;
import reactor.core.publisher.Mono;
import reactor.core.scheduler.Schedulers;

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
  private static final String MAIL_VALID_TIME_FORMAT = "yyyy-MM-dd HH:mm";
  /**
   * OTP ?????? - 2??? ???????????? ??? ??????????????? ????????????.
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
                        // 2??? ?????? ??????
                        log.debug("2??? ?????? ??????");
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
                                          userAccount.setLoginFailCount(0);   // ????????? ????????? ????????? ???????????? ?????????
                                          userAccount.setLoginFailDate(null); // ????????? ????????? ????????? ???????????? ?????????
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

    // 1??? ???????????? OTP ?????? ????????? ??? ?????? ??????(??????????????? - ??????????????? ??????)
    if (otpHistoryOptional.isPresent()) {
      return Mono.error(new UnauthorizedException(INVALID_OTP_NUMBER));
    }
    return Mono.empty();
  }

  public Mono<CheckResultResponse> otpResetPasswordValid(LrcOtpRequest request) {
    // Token Validation check and otp no check
    log.debug("otp validation check start => {}", request);

    String encodeKey = AES256Util.decryptAES(config.getCryptoKey(), request.getData2());
    OtpRequest otpRequest = new OtpRequest();
    otpRequest.setSiteId(SecurityConstant.LRC_SITE_ID);
    otpRequest.setOtpNo(request.getOtpNo());
    return
            checkExpiredOTP(otpRequest, encodeKey)
                    .then(
                            // ???????????? ?????? ??????
                            passwordResetTokenValidate(request.getData1())
                                    .flatMap(userAccount -> {
                                        // success token validation check
                                        // otp validation check
                                        if (OtpUtil.otpCheckCode(request.getOtpNo(), encodeKey)) {
                                            // otp ?????? ?????? ????????????
                                            return userAccountDomainService.getEmailToken(request.getData1())
                                                    .flatMap(lrcEmailToken -> {
                                                        lrcEmailToken.setCheckOtp(true);
                                                        return userAccountDomainService.updateEmailToken(lrcEmailToken).flatMap(emailToken -> {
                                                            return Mono.just(CheckResultResponse.builder().result(true).build());
                                                        });
                                            });
                                        } else {
                                            log.debug("OTP check error");
                                            return Mono.error(new UnauthorizedException(INVALID_OTP_NUMBER));
                                        }
                                    })
                    );
  }

    /**
     * ???????????? ???????????? ????????? ????????? ?????? ??????
     * @param paramToken
     * @return
     */
    public Mono<LrcAccount> passwordResetTokenValidate(String paramToken) {
        try{
            EmailValidKey keyData = getValidKey(paramToken);
            DateTimeFormatter format = DateTimeFormat.forPattern(MAIL_VALID_TIME_FORMAT);
            DateTime validDate = format.parseDateTime(keyData.getTime());
            Duration duration = new Duration(validDate, new DateTime());
            long time = duration.getStandardSeconds();
            if(time > 600){
                return Mono.error(new LrcUnauthorizedException(ErrorCode.FAIL_PASSWORD_RESET_EXPIRE));
            }
            return userAccountDomainService.getEmailToken(paramToken).flatMap(emailToken -> {
                if (emailToken.getCompleteYn()) {
                    return Mono.error(new LrcUnauthorizedException(ErrorCode.FAIL_PASSWORD_RESET_EXPIRE));
                }
                return userAccountDomainService.findById(keyData.getUserAccountId())
                        .switchIfEmpty(Mono.error(new LrcUnauthorizedException(ErrorCode.FAIL_PASSWORD_EMAIL_NOTFOUND)))
                        .flatMap(userAccount -> {
                            return Mono.just(userAccount);
                        });
            }).switchIfEmpty(Mono.error(new LrcUnauthorizedException(ErrorCode.FAIL_PASSWORD_RESET_EXPIRE)));
        }catch(Exception ex){
            return Mono.error(new LrcUnauthorizedException(ErrorCode.FAIL_PASSWORD_RESET));
        }
    }

    /**
     * ???????????? ???????????? ????????? OTP ????????? ????????? ??????
     * @param request
     * @return
     */
    public Mono<ResetInfoResponse> passwordResetTokenCheck(LrcResetRequest request) {
        return passwordResetTokenValidate(request.getData())
                .switchIfEmpty(Mono.error(new LrcUnauthorizedException(ErrorCode.FAIL_PASSWORD_EMAIL_NOTFOUND)))
                .flatMap(userAccount -> {
                    String decryptEmail = AES256Util.decryptAES(config.getKmsKey(), userAccount.getEmail());
                    OtpResponse otpResponse = OtpUtil.generate(decryptEmail, config.getCryptoKey(), userAccount.getOtpSecretKey());
                    String encodeKey = otpResponse.getEncodeKey();
                    return Mono.just(ResetInfoResponse.builder().isExpire(false).validData(encodeKey).build());
                });
    }

    /**
     * ????????? ????????? ??? ??????
     * @param encValidKey
     * @return
     * @throws Exception
     */
    private EmailValidKey getValidKey(String encValidKey) throws Exception{
        byte[] bytes = Base64.decodeBase64(encValidKey.getBytes(StandardCharsets.UTF_8));
        String decodeValidKey = new String(bytes, StandardCharsets.UTF_8);
        String decryptValidKey = AES256Util.decryptAES(config.getKmsKey(), decodeValidKey);
        String time = decryptValidKey.substring(0, 16);
        String userAccountId = decryptValidKey.substring(16);
        return EmailValidKey.builder().time(time).userAccountId(userAccountId).build();
    }
}
