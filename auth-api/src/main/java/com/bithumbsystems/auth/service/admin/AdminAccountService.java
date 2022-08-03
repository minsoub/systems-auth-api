package com.bithumbsystems.auth.service.admin;

import static com.bithumbsystems.auth.core.model.enums.ErrorCode.EQUAL_CURRENT_PASSWORD;
import static com.bithumbsystems.auth.core.model.enums.ErrorCode.EQUAL_OLD_PASSWORD;
import static com.bithumbsystems.auth.core.model.enums.ErrorCode.INVALID_ACCOUNT_CLOSED;
import static com.bithumbsystems.auth.core.model.enums.ErrorCode.INVALID_TOKEN;
import static com.bithumbsystems.auth.core.model.enums.ErrorCode.INVALID_USER;
import static com.bithumbsystems.auth.core.model.enums.ErrorCode.INVALID_USER_PASSWORD;
import static com.bithumbsystems.auth.core.model.enums.ErrorCode.USER_ACCOUNT_DISABLE;

import com.bithumbsystems.auth.api.config.AwsConfig;
import com.bithumbsystems.auth.api.exception.authorization.UnauthorizedException;
import com.bithumbsystems.auth.core.model.auth.TokenInfo;
import com.bithumbsystems.auth.core.model.auth.TokenOtpInfo;
import com.bithumbsystems.auth.core.model.enums.ResultCode;
import com.bithumbsystems.auth.core.model.enums.TokenType;
import com.bithumbsystems.auth.core.model.request.OtpClearRequest;
import com.bithumbsystems.auth.core.model.request.OtpRequest;
import com.bithumbsystems.auth.core.model.request.UserRequest;
import com.bithumbsystems.auth.core.model.response.SingleResponse;
import com.bithumbsystems.auth.core.util.AES256Util;
import com.bithumbsystems.auth.data.mongodb.client.entity.AdminAccount;
import com.bithumbsystems.auth.data.mongodb.client.enums.Status;
import com.bithumbsystems.auth.data.mongodb.client.service.AdminAccountDomainService;
import java.time.LocalDate;
import java.time.LocalDateTime;
import lombok.RequiredArgsConstructor;
import lombok.extern.log4j.Log4j2;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import reactor.core.publisher.Mono;
import reactor.core.scheduler.Schedulers;
import software.amazon.awssdk.utils.StringUtils;

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

  private final AwsConfig config;
  /**
   * 사용자 1차 로그인
   *
   * @param userRequest the user request
   * @return mono mono
   */
  public Mono<TokenOtpInfo> login(Mono<UserRequest> userRequest) {
    return userRequest.flatMap(request -> authenticate(
            AES256Util.decryptAES(config.getCryptoKey(), request.getEmail())
            , AES256Util.decryptAES(config.getCryptoKey(), request.getPasswd())
        )
    );
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
  public Mono<AdminAccount> otpClear(Mono<OtpClearRequest> otpClearRequestMono) {
    return otpClearRequestMono.flatMap(
        request -> adminAccountDomainService.findByEmail(request.getEmail())
            .flatMap(result -> {
              result.setOtpSecretKey("");
              return adminAccountDomainService.save(result)
                  .flatMap(adminAccount -> {
                    adminAccount.setPassword("");
                    adminAccount.setId("");
                    return Mono.just(adminAccount);
                  });
            }));
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
    log.debug("email => {}, password => {}", email, password);
    return findByEmail(email)
        .flatMap(account -> {
          if(checkPasswordUpdatePeriod(account) && passwordEncoder.matches(password, account.getOldPassword())) {
            return Mono.error(new UnauthorizedException(EQUAL_OLD_PASSWORD));
          }
          if(passwordEncoder.matches(password, account.getPassword())) {
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

  private static boolean checkPasswordUpdatePeriod(AdminAccount account) {
    final var period = 3;
    if(account.getLastPasswordUpdateDate() == null && account.getCreateDate().isBefore(LocalDateTime.now().minusMonths(period))) {
      return true;
    } else if (account.getLastPasswordUpdateDate() == null ){
      return false;
    } else
      return account.getLastPasswordUpdateDate().isBefore(LocalDateTime.now().minusMonths(period));
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
          if (account.getStatus().equals(Status.DENY_ACCESS) || account.getStatus().equals(Status.CLOSED_ACCOUNT)) {
            return Mono.error(new UnauthorizedException(USER_ACCOUNT_DISABLE));
          } else if(account.getValidStartDate() != null && account.getValidEndDate() != null) {
            if(account.getValidStartDate().isAfter(LocalDate.now()) && account.getValidEndDate().isBefore(LocalDate.now())) {
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
        .switchIfEmpty(Mono.error(new UnauthorizedException(INVALID_TOKEN)));
  }

  private Mono<TokenOtpInfo> loginSuccess(AdminAccount account) {
    if(checkPasswordUpdatePeriod(account)) {
      account.setStatus(Status.CHANGE_PASSWORD);
    }
    return adminTokenService.generateTokenOne(account, TokenType.ACCESS)
        .publishOn(Schedulers.boundedElastic())
        .map(result -> {
          log.debug("generateToken => {}", result);
          result.setEmail(account.getEmail());
          result.setOtpInfo(
              otpService.generate(account.getEmail(),
                  account.getOtpSecretKey()));
          result.setOptKey(account.getOtpSecretKey());
          if(account.getLastLoginDate() == null || account.getLastPasswordUpdateDate() == null) {
            result.setStatus(Status.INIT_REQUEST);
          } else {
            result.setStatus(account.getStatus());
          }
          // OTP Login 후에 수행하는 것이 맞다.
//          if (StringUtils.isEmpty(account.getOtpSecretKey())) {
//            // otp_secret_key 등록.
//            log.debug("otp secret key is null => save data");
//            account.setOtpSecretKey(result.getOtpInfo().getEncodeKey());
//            account.setLastLoginDate(LocalDateTime.now());
//          }
//          account.setLoginFailCount(0L);
//
//          adminAccountDomainService.save(account).then()
//              .log("result completed...")
//              .subscribe();
          return result;
        });
  }

  private Mono<TokenOtpInfo> wrongPasswordProcess(AdminAccount account) {
    account.setLoginFailCount(account.getLoginFailCount() == null ? 1 : account.getLoginFailCount() + 1);
    if (account.getLoginFailCount() == 5) {
      account.setStatus(Status.CLOSED_ACCOUNT);
    }

    return adminAccountDomainService.save(account)
        .flatMap(result -> {
          if (account.getLoginFailCount() >= 5) {
            return Mono.error(new UnauthorizedException(INVALID_ACCOUNT_CLOSED));
          } else {
            return Mono.error(new UnauthorizedException(INVALID_USER_PASSWORD));
          }
        });
  }
}
