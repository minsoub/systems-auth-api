package com.bithumbsystems.auth.service.user;


import com.bithumbsystems.auth.api.config.AwsConfig;
import com.bithumbsystems.auth.api.exception.ErrorData;
import com.bithumbsystems.auth.api.exception.authorization.UnauthorizedException;
import com.bithumbsystems.auth.core.model.auth.TokenInfo;
import com.bithumbsystems.auth.core.model.auth.TokenOtpInfo;
import com.bithumbsystems.auth.core.model.enums.ResultCode;
import com.bithumbsystems.auth.core.model.enums.TokenType;
import com.bithumbsystems.auth.core.model.request.OtpRequest;
import com.bithumbsystems.auth.core.model.request.UserCaptchaRequest;
import com.bithumbsystems.auth.core.model.request.UserJoinRequest;
import com.bithumbsystems.auth.core.model.request.UserRequest;
import com.bithumbsystems.auth.core.model.request.token.AuthRequest;
import com.bithumbsystems.auth.core.model.response.OtpResponse;
import com.bithumbsystems.auth.core.model.response.SingleResponse;
import com.bithumbsystems.auth.core.model.response.token.TokenResponse;
import com.bithumbsystems.auth.core.util.AES256Util;
import com.bithumbsystems.auth.data.mongodb.client.entity.UserAccount;
import com.bithumbsystems.auth.data.mongodb.client.enums.Status;
import com.bithumbsystems.auth.data.mongodb.client.enums.UserStatus;
import com.bithumbsystems.auth.data.mongodb.client.service.UserAccountDomainService;
import com.bithumbsystems.auth.service.AuthService;
import com.bithumbsystems.auth.service.admin.OtpService;
import com.bithumbsystems.auth.service.cipher.RsaCipherService;
import lombok.RequiredArgsConstructor;
import lombok.extern.log4j.Log4j2;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.util.StringUtils;
import org.springframework.web.reactive.function.server.ServerRequest;
import org.springframework.web.reactive.function.server.ServerResponse;
import reactor.core.publisher.Mono;

import java.time.Duration;
import java.time.LocalDateTime;

import static com.bithumbsystems.auth.core.model.enums.ErrorCode.*;

/**
 * The type User service.
 */
@Service
@Log4j2
@RequiredArgsConstructor
public class UserService {

  private final UserAccountDomainService userAccountDomainService;
  private final UserTokenService userTokenService;
  private final AwsConfig config;
  private final OtpService otpService;
  private final PasswordEncoder passwordEncoder;

  private final CaptchaService captchaService;
  private final RsaCipherService rsaCipherService;
  private final AuthService authService;
  private static final int PASSWORD_EXPIRE_DAY = 90;    // 비밀번호 만료일
  /**
   * 일반 사용자 로그인 처리 - 1차 로그인
   *
   * @param userRequest the user request
   * @return mono mono
   */
  public Mono<TokenOtpInfo> userLogin(Mono<UserRequest> userRequest) {
    return authService.getRsaPrivateKey()
        .flatMap(privateKey -> userRequest.flatMap(request -> authenticateUser(
                rsaCipherService.decryptRSA(request.getEmail(), privateKey)
                , rsaCipherService.decryptRSA(request.getPasswd(), privateKey)
                , request.getSiteId()
            ))
        );
  }

  /**
   * 일반 사용자 로그인 처리 - 1차 로그인 with captcha
   *
   * @param userCaptchaRequest the user captcha request
   * @return mono mono
   */
  public Mono<TokenOtpInfo> userCaptchaLogin(Mono<UserCaptchaRequest> userCaptchaRequest) {
    return authService.getRsaPrivateKey()
        .flatMap(privateKey ->
            userCaptchaRequest.flatMap(request -> captchaService.doVerify(request.getCaptcha())
                .flatMap(result -> {
                  if (result) {
                    return authenticateUser(
                        rsaCipherService.decryptRSA(request.getEmail(), privateKey)
                        , rsaCipherService.decryptRSA(request.getPasswd(), privateKey)
                        , request.getSiteId()
                    ).switchIfEmpty(Mono.error(new UnauthorizedException(AUTHENTICATION_FAIL)));
                  }
                  return Mono.error(new UnauthorizedException(CAPTCHA_FAIL));
                })));
  }

  /**
   * 사용자 가입을 처리한다.
   *
   * @param joinRequest the join request
   * @return mono mono
   */
  public Mono<SingleResponse> join(Mono<UserJoinRequest> joinRequest) {
    log.debug("join called...");
    return joinRequest.flatMap(req -> {
      String encryptEmail = AES256Util.encryptAES(config.getKmsKey(), req.getEmail(), config.getSaltKey(), config.getIvKey());
      return Mono.defer(() -> userAccountDomainService.findByEmail(encryptEmail)
          .map(result -> {
            log.debug("join method fail result => {}", result);
            ErrorData error = new ErrorData(EXISTED_USER);
            return new SingleResponse(error, ResultCode.ERROR);
          })
          .switchIfEmpty(Mono.defer(() -> userRegister(req))));
    });
  }

  /**
   * 사용자 정보를 신규 등록한다.
   *
   * @param req
   * @return
   */
  private Mono<SingleResponse> userRegister(UserJoinRequest req) {
    String email = AES256Util.encryptAES(config.getKmsKey(), req.getEmail(), config.getSaltKey(), config.getIvKey());
    String name = AES256Util.encryptAES(config.getKmsKey(), req.getName(), config.getSaltKey(), config.getIvKey());
    String phone = AES256Util.encryptAES(config.getKmsKey(), req.getPhone(), config.getSaltKey(), config.getIvKey());

    log.debug("userRegister email => {}", email);
    log.debug("userRegister name => {}", name);
    log.debug("userRegister phone => {}", phone);

    UserAccount user = UserAccount.builder()
        .email(email)  // config.encrypt(req.getEmail()))
        .name(name)    // config.encrypt(req.getName()))
        .password(passwordEncoder.encode(req.getPassword()))
        .phone(phone)  // config.encrypt(req.getPhone()))
        .snsId(req.getSnsId())
        .status(UserStatus.NORMAL)
        .loginFailCount(0)
        .createDate(LocalDateTime.now())
        .createAccountId("admin")
        .build();

    log.debug("user account data : {}", user);
    return userAccountDomainService.save(user)
        .map(r -> {
          log.debug("success => {}", r);
          return new SingleResponse("가입을 완료하였습니다!!!");
        });
  }

  /**
   * 1차 인증 후 사용자 Otp 생성
   *
   * @param email
   * @param password
   * @param siteId
   * @return
   */
  private Mono<TokenOtpInfo> authenticateUser(String email, String password, String siteId) {
      log.debug("email:{}", email);
      log.debug("getKmsKey():{}", config.getKmsKey());
      log.debug("getSaltKey():{}", config.getSaltKey());
      log.debug("getIvKey():{}", config.getIvKey());
      String encryptEmail = AES256Util.encryptAES(config.getKmsKey(), email, config.getSaltKey(), config.getIvKey());
    return userAccountDomainService.findByEmail(encryptEmail)
        .flatMap(account -> {
          log.debug("result account data => {}", account);
          if (account.getStatus().equals(UserStatus.EMAIL_VALID)) {
            return Mono.error(new UnauthorizedException(USER_ACCOUNT_EMAIL_VALID));
          } else if (!account.getStatus().equals(UserStatus.NORMAL)) {
            return Mono.error(new UnauthorizedException(USER_ACCOUNT_DISABLE));
          }
          int failCount = account.getLoginFailCount() == null ? 0 : account.getLoginFailCount();
          if (!passwordEncoder.matches(password, account.getPassword())) {
            // 로그인 실패 횟수 누적
            failCount = failCount + 1;

            // 5회이상 실패시 5분 후 다시 시도가능
            if (account.getLoginFailCount() != null && account.getLoginFailCount() >= 5) {
              if (isValidLoginFailTime(account.getLoginFailDate())) {
                // 5분이 아직 지나지 않았으면 실패 메시지 출력
                return Mono.error(new UnauthorizedException(MAXIMUM_AUTH_ATTEMPTS_EXCEEDED));
              } else {
                // 5분이 지났으면 실패횟수를 1로 초기화
                failCount = 1;
              }
            }
            // 로그인 실패 횟수를 저장하고 에러 리턴
            account.setLoginFail(failCount);
            return userAccountDomainService.save(account).flatMap(userAccount -> {
              if (userAccount.getLoginFailCount() >= 5) {
                //5회 이상 실패시
                return Mono.error(new UnauthorizedException(MAXIMUM_AUTHENTICATION_FAIL));
              } else {
                return Mono.error(new UnauthorizedException(LOGIN_USER_NOT_MATCHED));
              }
            });
          }

          //5회이상 실패 후 5분간 로그인 금지
          if (failCount == 5 && isValidLoginFailTime(account.getLoginFailDate())) {
            return Mono.error(new UnauthorizedException(MAXIMUM_AUTH_ATTEMPTS_EXCEEDED));
          }

          //비밀번호 변경일 체크(비밀번호 사용기간 제한)
          LocalDateTime checkDateTime = (account.getChangePasswordDate() == null)? account.getCreateDate() : account.getChangePasswordDate();
          if(checkDateTime == null) {
              return Mono.error(new UnauthorizedException(EXPIRED_PASSWORD));
          }else{
              Duration duration = Duration.between(checkDateTime, LocalDateTime.now());
              long sec = duration.getSeconds();
              //3개월
              long durationDate = sec / 60 / 60 / 24;
              if(PASSWORD_EXPIRE_DAY < durationDate){
                  return Mono.error(new UnauthorizedException(EXPIRED_PASSWORD));
              }
          }
            String decryptEmail = AES256Util.decryptAES(config.getKmsKey(), account.getEmail());
            return userTokenService.generateTokenOne(account, decryptEmail, TokenType.ACCESS)
                    .flatMap(tokenOtpInfo -> {
                        log.debug("authenticateUser-generateToken => {}", tokenOtpInfo);
                        tokenOtpInfo.setEmail(AES256Util.encryptAES(config.getCryptoKey(), account.getEmail()));
                        if(StringUtils.hasLength(account.getName())){
                            tokenOtpInfo.setName( AES256Util.encryptAES(config.getCryptoKey(), account.getName())); // name add
                        }else{
                            tokenOtpInfo.setName("");
                        }
                        tokenOtpInfo.setIsCode(StringUtils.hasLength(account.getOtpSecretKey()));
                        OtpResponse otpResponse = otpService.generate(decryptEmail, account.getOtpSecretKey());
                        tokenOtpInfo.setValidData(otpResponse.getEncodeKey());
                        String status = account.getStatus().name();
                        log.debug("status:{}", status);
                        if((Status.NORMAL.toString()).equals(status)){
                            tokenOtpInfo.setStatus(Status.NORMAL);
                        }
                        return Mono.just(tokenOtpInfo);
                    });
/*
          return userTokenService.generateToken(TokenGenerateRequest.builder()
              .accountId(account.getId())
              .roles("USER")
              .siteId(siteId)
              .email(account.getEmail())
              .claims(Map.of("ROLE", "USER", "account_id", account.getId()))
              .build())
              .publishOn(Schedulers.boundedElastic())
              .map(result -> {
                log.debug("generateToken => {}", result);
                account.setLastLoginDate(LocalDateTime.now());
                account.setLoginFailCount(0);   // 로그인 성공시 로그인 실패횟수 초기화
                account.setLoginFailDate(null); // 로그인 성공시 로그인 실패시간 초기화
                userAccountDomainService.save(account).then().log("result completed...")
                    .subscribe();
                  result.setEmail(AES256Util.encryptAES(config.getLrcCryptoKey(), AES256Util.decryptAES(config.getKmsKey(), result.getEmail()))); // 이메일을 복호화 하여 통신구간 암호화 처리 후 fe로 내려준다.
                return result;
              });

 */
        })
        .switchIfEmpty(Mono.error(new UnauthorizedException(LOGIN_USER_NOT_MATCHED)));
  }

  public Mono<TokenResponse> reGenerateToken(Mono<AuthRequest> authRequest) {
    return userTokenService.reGenerateToken(authRequest);
  }

  private boolean isValidLoginFailTime(LocalDateTime failTime) {
    if (failTime == null) {
      return false;
    }
    Duration between = Duration.between(failTime, LocalDateTime.now());
    long sec = between.getSeconds();
    log.debug("time duration:{}, {}, {}", sec, failTime.toString(), LocalDateTime.now().toString());
    // 5분이 지남
    return sec <= 300;
  }

    /**
     * 사용자 2차 로그인 (otp 로그인)
     *
     * @param otpRequest the otp request
     * @return mono mono
     */
    public Mono<TokenInfo> otp(Mono<OtpRequest> otpRequest) {
        return otpRequest.flatMap(otpService::otpValidationForUser);
    }
}
