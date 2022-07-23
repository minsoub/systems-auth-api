package com.bithumbsystems.auth.service.user;


import static com.bithumbsystems.auth.core.model.enums.ErrorCode.AUTHENTICATION_FAIL;
import static com.bithumbsystems.auth.core.model.enums.ErrorCode.CAPTCHA_FAIL;
import static com.bithumbsystems.auth.core.model.enums.ErrorCode.EXISTED_USER;
import static com.bithumbsystems.auth.core.model.enums.ErrorCode.INVALID_USERNAME;
import static com.bithumbsystems.auth.core.model.enums.ErrorCode.INVALID_USER_PASSWORD;
import static com.bithumbsystems.auth.core.model.enums.ErrorCode.MAXIMUM_AUTHENTICATION_FAIL;
import static com.bithumbsystems.auth.core.model.enums.ErrorCode.MAXIMUM_AUTH_ATTEMPTS_EXCEEDED;
import static com.bithumbsystems.auth.core.model.enums.ErrorCode.USER_ACCOUNT_DISABLE;
import static com.bithumbsystems.auth.core.model.enums.ErrorCode.USER_ACCOUNT_EMAIL_VALID;

import com.bithumbsystems.auth.api.config.AwsConfig;
import com.bithumbsystems.auth.api.config.property.JwtProperties;
import com.bithumbsystems.auth.api.exception.ErrorData;
import com.bithumbsystems.auth.api.exception.authorization.UnauthorizedException;
import com.bithumbsystems.auth.core.model.auth.GenerateTokenInfo;
import com.bithumbsystems.auth.core.model.auth.TokenInfo;
import com.bithumbsystems.auth.core.model.enums.ResultCode;
import com.bithumbsystems.auth.core.model.enums.TokenType;
import com.bithumbsystems.auth.core.model.request.UserCaptchaRequest;
import com.bithumbsystems.auth.core.model.request.UserJoinRequest;
import com.bithumbsystems.auth.core.model.request.UserRequest;
import com.bithumbsystems.auth.core.model.response.SingleResponse;
import com.bithumbsystems.auth.core.util.AES256Util;
import com.bithumbsystems.auth.core.util.JwtGenerateUtil;
import com.bithumbsystems.auth.data.mongodb.client.entity.UserAccount;
import com.bithumbsystems.auth.data.mongodb.client.enums.UserStatus;
import com.bithumbsystems.auth.data.mongodb.client.service.UserAccountDomainService;
import com.bithumbsystems.auth.data.redis.RedisTemplateSample;
import java.time.Duration;
import java.time.LocalDateTime;
import java.util.Map;
import lombok.RequiredArgsConstructor;
import lombok.extern.log4j.Log4j2;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import reactor.core.publisher.Mono;
import reactor.core.scheduler.Schedulers;

/**
 * The type User service.
 */
@Service
@Log4j2
@RequiredArgsConstructor
public class UserService {

  private final JwtProperties jwtProperties;
  private final UserAccountDomainService userAccountDomainService;
  private final RedisTemplateSample redisTemplateSample;
  private final AwsConfig config;

  private final PasswordEncoder passwordEncoder;

  private final CaptchaService captchaService;

  /**
   * 일반 사용자 로그인 처리 - 1차 로그인
   *
   * @param userRequest the user request
   * @return mono mono
   */
  public Mono<TokenInfo> userLogin(Mono<UserRequest> userRequest) {
    return userRequest.flatMap(request -> authenticateUser(
            AES256Util.decryptAES(AES256Util.CLIENT_AES_KEY_LRC, request.getEmail())
            , AES256Util.decryptAES(AES256Util.CLIENT_AES_KEY_LRC, request.getPasswd())
            , request.getSiteId()
        )
    );
  }

  /**
   * 일반 사용자 로그인 처리 - 1차 로그인 with captcha
   *
   * @param userCaptchaRequest the user captcha request
   * @return mono mono
   */
  public Mono<TokenInfo> userCaptchaLogin(Mono<UserCaptchaRequest> userCaptchaRequest) {
    return userCaptchaRequest.flatMap(request -> {
      return captchaService.doVerify(request.getCaptcha())
          .flatMap(result -> {
            if (result) {
              return authenticateUser(
                  AES256Util.decryptAES(AES256Util.CLIENT_AES_KEY_LRC, request.getEmail())
                  , AES256Util.decryptAES(AES256Util.CLIENT_AES_KEY_LRC, request.getPasswd())
                  , request.getSiteId()
              ).switchIfEmpty(Mono.error(new UnauthorizedException(AUTHENTICATION_FAIL)));
            }
            return Mono.error(new UnauthorizedException(CAPTCHA_FAIL));
          });
    });
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
      String encryptEmail = AES256Util.encryptAES(config.getKmsKey(), req.getEmail(), true);
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
    String email = AES256Util.encryptAES(config.getKmsKey(), req.getEmail(), true);
    String name = AES256Util.encryptAES(config.getKmsKey(), req.getName(), true);
    String phone = AES256Util.encryptAES(config.getKmsKey(), req.getPhone(), true);

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
  private Mono<TokenInfo> authenticateUser(String email, String password, String siteId) {
    return userAccountDomainService.findByEmail(
            AES256Util.encryptAES(config.getKmsKey(), email, true))
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
                return Mono.error(new UnauthorizedException(INVALID_USER_PASSWORD));
              }
            });
          }

          //5회이상 실패 후 5분간 로그인 금지
          if (failCount == 5 && isValidLoginFailTime(account.getLoginFailDate())) {
            return Mono.error(new UnauthorizedException(MAXIMUM_AUTH_ATTEMPTS_EXCEEDED));
          }

          return generateToken(account, siteId)
              .map(result -> {
                log.debug("generateToken => {}", result);

                account.setLastLoginDate(LocalDateTime.now());
                account.setLoginFailCount(0);   // 로그인 성공시 로그인 실패횟수 초기화
                account.setLoginFailDate(null); // 로그인 성공시 로그인 실패시간 초기화
                userAccountDomainService.save(account).then().log("result completed...")
                    .subscribe();
                return result;
              });
        })
        .switchIfEmpty(Mono.error(new UnauthorizedException(INVALID_USERNAME)));
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
   * 1차 토큰 생성
   *
   * @param account
   * @param siteId
   * @return
   */
  private Mono<TokenInfo> generateToken(UserAccount account, String siteId) {

    log.debug("generateTokenOne create......{}", account.getId());
    return userAccountDomainService.findById(account.getId())
        .publishOn(Schedulers.boundedElastic())
        .map(result -> {
          log.debug("admin_access data => {}", result);
          GenerateTokenInfo generateTokenInfo = GenerateTokenInfo
              .builder()
              .secret(jwtProperties.getSecret())
              .expiration(jwtProperties.getExpiration().get(TokenType.ACCESS.getValue()))
              .refreshExpiration(jwtProperties.getExpiration().get(TokenType.REFRESH.getValue()))
              .subject(siteId)
              .issuer(account.getEmail())
              .claims(Map.of("ROLE", "USER", "account_id", account.getId()))  // 지금은 인증
              .build();

          var tokenInfo = JwtGenerateUtil.generate(generateTokenInfo)
              .toBuilder()
              .build();
          redisTemplateSample.saveToken(account.getEmail() + "::LRC", tokenInfo.toString())
              .log("result -> save success..").subscribe();
          return tokenInfo;
        })
        .switchIfEmpty(Mono.error(new UnauthorizedException(INVALID_USERNAME)));
  }


}