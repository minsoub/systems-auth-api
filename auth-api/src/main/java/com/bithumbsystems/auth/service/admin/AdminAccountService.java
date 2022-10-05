package com.bithumbsystems.auth.service.admin;

import static com.bithumbsystems.auth.core.model.enums.ErrorCode.*;
import static com.bithumbsystems.auth.service.admin.validator.AdminAccountValidator.checkPasswordUpdatePeriod;
import static com.bithumbsystems.auth.service.admin.validator.AdminAccountValidator.isValidPassword;

import com.bithumbsystems.auth.api.config.AwsConfig;
import com.bithumbsystems.auth.api.config.properties.JwtProperties;
import com.bithumbsystems.auth.api.exception.authorization.UnauthorizedException;
import com.bithumbsystems.auth.core.model.auth.GenerateTokenInfo;
import com.bithumbsystems.auth.core.model.auth.TokenInfo;
import com.bithumbsystems.auth.core.model.auth.TokenOtpInfo;
import com.bithumbsystems.auth.core.model.enums.MailForm;
import com.bithumbsystems.auth.core.model.enums.ResultCode;
import com.bithumbsystems.auth.core.model.enums.TokenType;
import com.bithumbsystems.auth.core.model.request.*;
import com.bithumbsystems.auth.core.model.response.OtpResponse;
import com.bithumbsystems.auth.core.model.response.SingleResponse;
import com.bithumbsystems.auth.core.util.AES256Util;
import com.bithumbsystems.auth.core.util.JwtVerifyUtil;
import com.bithumbsystems.auth.core.util.message.MessageService;
import com.bithumbsystems.auth.data.authentication.entity.AdminAccount;
import com.bithumbsystems.auth.data.authentication.enums.Status;
import com.bithumbsystems.auth.data.authentication.service.AdminAccountDomainService;
import com.bithumbsystems.auth.data.redis.AuthRedisService;
import com.bithumbsystems.auth.service.AuthService;
import com.bithumbsystems.auth.service.cipher.RsaCipherService;
import io.jsonwebtoken.Claims;
import java.time.LocalDate;
import java.time.LocalDateTime;
import java.util.Date;
import java.util.Map;
import java.util.UUID;

import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.security.Keys;
import lombok.RequiredArgsConstructor;
import lombok.extern.log4j.Log4j2;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.util.StringUtils;
import reactor.core.publisher.Mono;
import reactor.core.scheduler.Schedulers;

/**
 * 관리자/운영자 위한 인증 관련 클래스
 */
@Service
@Log4j2
@RequiredArgsConstructor
public class AdminAccountService {

  private final AdminAccountDomainService adminAccountDomainService;
  private final OtpService otpService;
  private final AdminTokenService adminTokenService;
  private final PasswordEncoder passwordEncoder;
  private final MessageService messageService;
  private final AwsConfig config;
  private final RsaCipherService rsaCipherService;
  private final AuthService authService;

  private final JwtProperties jwtProperties;

    private final AuthRedisService authRedisService;

  /**
   * 사용자 1차 로그인
   *
   * @param userRequest the user request
   * @return mono mono
   */
  public Mono<TokenOtpInfo> login(Mono<UserRequest> userRequest) {
    return authService.getRsaPrivateKey()
        .flatMap(privateKey -> userRequest.flatMap(request -> authenticate(
                rsaCipherService.decryptRSA(request.getEmail(), privateKey)
                , rsaCipherService.decryptRSA(request.getPasswd(), privateKey)
            )));
  }

  /**
   * 패스워드 변경
   *
   * @param userRequest the user request
   * @return mono
   */
  public Mono<SingleResponse<String>> passwordUpdate(Mono<UserRequest> userRequest) {
    return userRequest.flatMap(request -> passwordUpdate(
            AES256Util.decryptAES(config.getCryptoKey(), request.getEmail())
            , AES256Util.decryptAES(config.getCryptoKey(), request.getPasswd())
            , AES256Util.decryptAES(config.getCryptoKey(), request.getCurrentPasswd())
        ).map(result -> new SingleResponse<>("OK", ResultCode.SUCCESS))
    );
  }

  /**
   * 사용자 2차 로그인 (otp 로그인)
   *
   * @param otpRequest the otp request
   * @return mono mono
   */
  public Mono<TokenInfo> otp(Mono<OtpRequest> otpRequest) {
    return otpRequest.flatMap(otpService::otpValidation);
  }

  /**
   * 사용자 OTP 정보를 클리어 한다.
   *
   * @param otpClearRequestMono the otp clear request mono
   * @return mono
   */
  public Mono<SingleResponse> otpClear(Mono<OtpClearRequest> otpClearRequestMono) {
    return otpClearRequestMono.flatMap(
            request -> {
                // 1차 토큰 로직 추가.
                Claims check = JwtVerifyUtil.getAllClaimsFromToken(request.getToken(), jwtProperties.getSecret());
                if (check == null) {
                    return Mono.error(new UnauthorizedException(USER_ACCOUNT_DISABLE));
                }
                String checkEmail = check.getIssuer();
                if (checkEmail == null) {
                    return Mono.error(new UnauthorizedException(USER_ACCOUNT_DISABLE));
                } else {
                    // 메일 주소 체크.
                    String decryptEmail = AES256Util.decryptAES(config.getCryptoKey(), request.getEmail());
                    log.debug("decryptEmail => {}", decryptEmail);
                    log.debug("checkEmail => {}", checkEmail);
                    if (!decryptEmail.equals(checkEmail)) {
                        return Mono.error(new UnauthorizedException(USER_ACCOUNT_DISABLE));
                    }
                }

        return adminAccountDomainService.findByEmail(AES256Util.decryptAES(config.getCryptoKey(), request.getEmail()))
            .flatMap(result -> {
              result.setStatus(Status.INIT_OTP_REQUEST);
              return adminAccountDomainService.save(result)
                  .flatMap(adminAccount -> {
                    adminAccount.setPassword(null);
                    adminAccount.setId("");
                    return Mono.just(adminAccount);
                  });
            });
            }).map(result -> new SingleResponse<>("OK", ResultCode.SUCCESS));
  }


  /**
   * Find by email mono.
   *
   * @param email the email
   * @return the mono
   */
  public Mono<AdminAccount> findByEmail(String email) {
    return adminAccountDomainService.findByEmail(email)
        .switchIfEmpty(Mono.error(new UnauthorizedException(INVALID_USER)));
  }

  /**
   * 패스워드 정보를 수정한다. (임시 비밀번호 발급 후 패스워드 수정)
   *
   * @param email    the email
   * @param password the password
   * @return mono
   */
  public Mono<AdminAccount> passwordUpdate(String email, String password, String currentPassword) {
    return findByEmail(email)
        .flatMap(account -> {
          if(!isValidPassword(password)) {
            return Mono.error(new UnauthorizedException(USER_ACCOUNT_DISABLE));
          }
          if (!passwordEncoder.matches(currentPassword, account.getPassword())) {
              log.debug("current password not equals {}", currentPassword);
              return Mono.error(new UnauthorizedException(USER_ACCOUNT_DISABLE));
          }
          if (checkPasswordUpdatePeriod(account) && passwordEncoder.matches(password,
              account.getOldPassword())) {
            return Mono.error(new UnauthorizedException(USER_ACCOUNT_DISABLE));
          }
          if (passwordEncoder.matches(password, account.getPassword())) {
            return Mono.error(new UnauthorizedException(USER_ACCOUNT_DISABLE));
          }
          account.setOldPassword(account.getPassword());
          account.setPassword(passwordEncoder.encode(password));
          account.setStatus(Status.NORMAL);
          account.setLastPasswordUpdateDate(LocalDateTime.now());
          account.setUpdateDate(LocalDateTime.now());
          account.setUpdateAdminAccountId(account.getId());
          return adminAccountDomainService.save(account);
        });
  }

  /**
   * 사용자 인증 처리 - 1차
   *
   * @param email    the email
   * @param password the password
   * @return mono mono
   */
  public Mono<TokenOtpInfo> authenticate(String email, String password) {
    return findByEmail(email)
        .flatMap(account -> {
          log.debug("result account data => {}", account);
          if (account.getStatus().equals(Status.DENY_ACCESS) || account.getStatus()
              .equals(Status.CLOSED_ACCOUNT)) {
            return Mono.error(new UnauthorizedException(USER_ACCOUNT_DISABLE));
          } else if (account.getValidStartDate() != null && account.getValidEndDate() != null) {
            if (account.getValidStartDate().isAfter(LocalDate.now()) && account.getValidEndDate()
                .isBefore(LocalDate.now())) {
              return Mono.error(new UnauthorizedException(USER_ACCOUNT_DISABLE));
            }
          }

          log.debug("password => {}", password);
          if (passwordEncoder.matches(password, account.getPassword())) {
            return loginSuccess(account);
          } else {
            return wrongPasswordProcess(account);
          }
        })
        .switchIfEmpty(Mono.error(new UnauthorizedException(USER_ACCOUNT_DISABLE)));
  }

  private Mono<TokenOtpInfo> loginSuccess(AdminAccount account) {
    if (checkPasswordUpdatePeriod(account)) {
      account.setStatus(Status.CHANGE_PASSWORD);
    }
    return adminTokenService.generateTokenOne(account, TokenType.ACCESS)
        .publishOn(Schedulers.boundedElastic())
        .map(result -> {
          log.debug("generateToken => {}", result);
          result.setEmail(AES256Util.encryptAES(config.getCryptoKey(), account.getEmail()));
          result.setName( AES256Util.encryptAES(config.getCryptoKey(), account.getName())); // name add
          result.setIsCode(StringUtils.hasLength(account.getOtpSecretKey()));
          OtpResponse otpResponse = otpService.generate(account.getEmail(), account.getOtpSecretKey());
          result.setValidData(otpResponse.getEncodeKey());
          if (account.getLastLoginDate() == null || account.getLastPasswordUpdateDate() == null) {
            result.setStatus(Status.INIT_REQUEST);
          } else {
            result.setStatus(account.getStatus());
          }
          return result;
        });
  }

    /**
     * 패스워드 오류 시 실패에 대한 저장.
     * @param account
     * @return
     */
  private Mono<TokenOtpInfo> wrongPasswordProcess(AdminAccount account) {
    account.setLoginFailCount(
        account.getLoginFailCount() == null ? 1 : account.getLoginFailCount() + 1);
    if (account.getLoginFailCount() == 5) {
      account.setStatus(Status.CLOSED_ACCOUNT);
    }

    return adminAccountDomainService.save(account)
        .flatMap(result -> Mono.error(new UnauthorizedException(USER_ACCOUNT_DISABLE)));
  }

    /**
     * 임시 비밀번호 요청 검증을 위한 CONFIRM 메일을 전송한다.
     *
     * @param adminRequestMono
     * @return
     */
    public Mono<SingleResponse> sendTempPasswordInit(Mono<AdminRequest> adminRequestMono) {
        return adminRequestMono
                .flatMap(adminRequest -> {
                    log.debug(AES256Util.decryptAES(config.getCryptoKey(), adminRequest.getEmail()));
                    return findByEmail(AES256Util.decryptAES(config.getCryptoKey(), adminRequest.getEmail()));
                })
                .flatMap(account -> {
                    // 임시 빌밀번호가 발급 가능한 계정상태이진 체크한다.
                    if (account.getStatus().equals(Status.CLOSED_ACCOUNT) || account.getStatus().equals(Status.DENY_ACCESS)) {
                        return Mono.error(new UnauthorizedException(USER_ACCOUNT_DISABLE));
                    }

                    return makeConfirmUrl(account.getEmail())
                            .flatMap(result -> {
                                log.debug(result);
                               messageService.sendInitMail(account.getEmail(), result, MailForm.CONFIRM);
                               return Mono.just(new SingleResponse<>("OK", ResultCode.SUCCESS));
                            });
                });
    }

    /**
     * 임시 비밀번호를 발송한다.
     *
     * @param adminRequestMono
     * @return
     */
  public Mono<SingleResponse> sendTempPasswordMail(Mono<AdminTempRequest> adminRequestMono) {
    return adminRequestMono
        .flatMap(adminRequest -> {

            log.debug("validData => {}", adminRequest.getValidData());
            if (!StringUtils.hasLength(adminRequest.getValidData())) {
                log.debug("token check error...");
                return Mono.error(new UnauthorizedException(USER_ACCOUNT_DISABLE));
            }

            // Token Validation Check
            String email = AES256Util.decryptAES(config.getCryptoKey(), adminRequest.getEmail());
            // Token 분석
            return JwtVerifyUtil.check(adminRequest.getValidData(), jwtProperties.getSecret())
                    .flatMap(validResult -> {
                        String validEmail = AES256Util.decryptAES(config.getCryptoKey(), validResult.claims.getIssuer());
                        if (!email.equals(validEmail)) {
                            log.debug("email validation check error");
                            return Mono.error(new UnauthorizedException(USER_ACCOUNT_DISABLE));
                        }
                        return Mono.just(true);
                    })
                    .flatMap(r -> {
                        return findByEmail(email);
                    });
        })
        .flatMap(account -> {
          if (account.getStatus().equals(Status.CLOSED_ACCOUNT) || account.getStatus().equals(Status.DENY_ACCESS)) {
            return Mono.error(new UnauthorizedException(USER_ACCOUNT_DISABLE));
          }
          String password = makeTempPassword();
          messageService.sendMail(account.getEmail(), password, MailForm.DEFAULT);
          account.setOldPassword(account.getPassword());
          account.setPassword(passwordEncoder.encode(password));
          account.setStatus(Status.INIT_REQUEST);
          account.setLastPasswordUpdateDate(null);
          account.setUpdateDate(LocalDateTime.now());
          account.setUpdateAdminAccountId(account.getId());
          return adminAccountDomainService.save(account)
                  .map(result -> new SingleResponse<>("OK", ResultCode.SUCCESS));
        });
  }

  private static String makeTempPassword() {
    return String.valueOf(System.currentTimeMillis()).substring(0, 3)
        + UUID.randomUUID().toString().replace("-", "").substring(0, 5)
        + String.valueOf(System.currentTimeMillis()).substring(3, 6);
  }

    /**
     * Confirm URL 생성
     *
     * @param email
     * @return
     */
  private Mono<String> makeConfirmUrl(String email) {
      // 5분 만료 토큰 생성
      GenerateTokenInfo generateTokenInfo = GenerateTokenInfo
              .builder()
              .secret(jwtProperties.getSecret())
              .expiration(jwtProperties.getAccessExpiration())
              .subject("User Identification")
              .issuer(AES256Util.encryptAES(config.getCryptoKey(), email))
              .claims(Map.of("account_id", AES256Util.encryptAES(config.getCryptoKey(), email)))  // 지금은 인증
              .build();

      // Token 생성.
      var createdDate = new Date();
      var expirationTimeInMilliseconds = 60 * 5 * 1000;  // 5 minute
      var refreshExpirationDate =  new Date(System.currentTimeMillis() + expirationTimeInMilliseconds);
      var token = Jwts.builder()
              .setClaims(generateTokenInfo.getClaims())
              .setIssuer(generateTokenInfo.getIssuer())
              .setSubject(generateTokenInfo.getSubject())
              .setIssuedAt(createdDate)
              .setId(UUID.randomUUID().toString())
              .setExpiration(refreshExpirationDate)
              .signWith(Keys.hmacShaKeyFor(generateTokenInfo.getSecret().getBytes()))
              .compact();

      // token을 저장하고 만료일을 5분으로 설정한다.
      // key 구분자는 email_confirm으로 한다.
      // 이미 등록되어 있으면 안된다.
      String redisKey = email+"_confirm";

      return authRedisService.getCheckKey(redisKey)
              .flatMap(r -> {
                  if (!r) {
                      return authRedisService.saveExpiration(token, redisKey, expirationTimeInMilliseconds/1000)
                              .flatMap(r2 -> Mono.just(token));
                  }else {
                      return Mono.error(new UnauthorizedException(TOKEN_EXISTS));
                  }
              });
  }
}
