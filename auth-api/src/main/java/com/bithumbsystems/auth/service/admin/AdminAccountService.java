package com.bithumbsystems.auth.service.admin;

import static com.bithumbsystems.auth.core.model.enums.ErrorCode.EQUAL_CURRENT_PASSWORD;
import static com.bithumbsystems.auth.core.model.enums.ErrorCode.EQUAL_OLD_PASSWORD;
import static com.bithumbsystems.auth.core.model.enums.ErrorCode.INVALID_USER;
import static com.bithumbsystems.auth.core.model.enums.ErrorCode.INVALID_USER_PASSWORD;
import static com.bithumbsystems.auth.core.model.enums.ErrorCode.USER_ACCOUNT_DISABLE;
import static com.bithumbsystems.auth.service.admin.validator.AdminAccountValidator.checkPasswordUpdatePeriod;
import static com.bithumbsystems.auth.service.admin.validator.AdminAccountValidator.isValidPassword;

import com.bithumbsystems.auth.api.config.AwsConfig;
import com.bithumbsystems.auth.api.config.properties.JwtProperties;
import com.bithumbsystems.auth.api.exception.authorization.UnauthorizedException;
import com.bithumbsystems.auth.core.model.auth.TokenInfo;
import com.bithumbsystems.auth.core.model.auth.TokenOtpInfo;
import com.bithumbsystems.auth.core.model.enums.MailForm;
import com.bithumbsystems.auth.core.model.enums.ResultCode;
import com.bithumbsystems.auth.core.model.enums.TokenType;
import com.bithumbsystems.auth.core.model.request.AdminRequest;
import com.bithumbsystems.auth.core.model.request.OtpClearRequest;
import com.bithumbsystems.auth.core.model.request.OtpRequest;
import com.bithumbsystems.auth.core.model.request.UserRequest;
import com.bithumbsystems.auth.core.model.response.SingleResponse;
import com.bithumbsystems.auth.core.util.AES256Util;
import com.bithumbsystems.auth.core.util.JwtVerifyUtil;
import com.bithumbsystems.auth.core.util.message.MessageService;
import com.bithumbsystems.auth.data.mongodb.client.entity.AdminAccount;
import com.bithumbsystems.auth.data.mongodb.client.enums.Status;
import com.bithumbsystems.auth.data.mongodb.client.service.AdminAccountDomainService;
import com.bithumbsystems.auth.service.AuthService;
import com.bithumbsystems.auth.service.cipher.RsaCipherService;
import io.jsonwebtoken.Claims;
import java.time.LocalDate;
import java.time.LocalDateTime;
import java.util.UUID;
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
  public Mono<AdminAccount> passwordUpdate(String email, String password) {
    return findByEmail(email)
        .flatMap(account -> {
          if(!isValidPassword(password)) {
            return Mono.error(new UnauthorizedException(INVALID_USER_PASSWORD));
          }
          if (checkPasswordUpdatePeriod(account) && passwordEncoder.matches(password,
              account.getOldPassword())) {
            return Mono.error(new UnauthorizedException(EQUAL_OLD_PASSWORD));
          }
          if (passwordEncoder.matches(password, account.getPassword())) {
            return Mono.error(new UnauthorizedException(EQUAL_CURRENT_PASSWORD));
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
          result.setOtpInfo(
              otpService.generate(account.getEmail(),
                  account.getOtpSecretKey()));
          result.setIsCode(StringUtils.hasLength(account.getOtpSecretKey()));
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

  public Mono<SingleResponse> sendTempPasswordMail(Mono<AdminRequest> adminRequestMono) {
    return adminRequestMono
        .flatMap(adminRequest -> {
          log.debug(AES256Util.decryptAES(config.getCryptoKey(), adminRequest.getEmail()));
          return findByEmail(AES256Util.decryptAES(config.getCryptoKey(), adminRequest.getEmail()));
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
}
