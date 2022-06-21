package com.bithumbsystems.auth.service;

import static com.bithumbsystems.auth.core.model.enums.ErrorCode.INVALID_TOKEN;
import static com.bithumbsystems.auth.core.model.enums.ErrorCode.INVALID_USER;
import static com.bithumbsystems.auth.core.model.enums.ErrorCode.INVALID_USER_PASSWORD;
import static com.bithumbsystems.auth.core.model.enums.ErrorCode.USER_ACCOUNT_DISABLE;
import static com.bithumbsystems.auth.core.util.JwtGenerateUtil.generateOtp;

import com.bithumbsystems.auth.api.config.property.JwtProperties;
import com.bithumbsystems.auth.api.exception.authorization.UnauthorizedException;
import com.bithumbsystems.auth.core.model.auth.GenerateTokenInfo;
import com.bithumbsystems.auth.core.model.auth.TokenInfo;
import com.bithumbsystems.auth.core.model.auth.TokenOtpInfo;
import com.bithumbsystems.auth.core.model.enums.TokenType;
import com.bithumbsystems.auth.core.model.request.OtpRequest;
import com.bithumbsystems.auth.core.model.request.UserRequest;
import com.bithumbsystems.auth.core.util.AES256Util;
import com.bithumbsystems.auth.data.mongodb.client.entity.AdminAccount;
import com.bithumbsystems.auth.data.mongodb.client.service.AdminAccessDomainService;
import com.bithumbsystems.auth.data.mongodb.client.service.AdminAccountDomainService;
import com.bithumbsystems.auth.data.mongodb.client.service.ClientDomainService;
import com.bithumbsystems.auth.data.mongodb.client.service.RoleManagementDomainService;
import com.bithumbsystems.auth.data.redis.RedisTemplateSample;
import java.time.LocalDateTime;
import java.util.Map;
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
public class AccountService {

    private final AdminAccountDomainService adminAccountDomainService;
    private final AdminAccessDomainService adminAccessDomainService;

    private final RoleManagementDomainService roleManagementDomainService;

    private final OtpService otpService;

    private final JwtProperties jwtProperties;

    private final ClientDomainService clientDomainService;

    private final RedisTemplateSample redisTemplateSample;
    private final PasswordEncoder passwordEncoder;
    private final AuthService jwtGenerateService;

    //private final AccountMapper accountMapper;

  /**
   * 사용자 1차 로그인
   *
   * @param userRequest the user request
   * @return mono mono
   */
  public Mono<TokenOtpInfo> login(Mono<UserRequest> userRequest) {
        return userRequest.flatMap(request -> authenticate(
                AES256Util.decryptAES( AES256Util.CLIENT_AES_KEY_ADM, request.getEmail() )
                , AES256Util.decryptAES( AES256Util.CLIENT_AES_KEY_ADM, request.getPasswd() )
                )
        );
    }

  /**
   * 사용자 2차 로그인 (otp 로그인)
   *
   * @param otpRequest the otp request
   * @return mono mono
   */
  public Mono<TokenInfo> otp(Mono<OtpRequest> otpRequest) {
        return otpRequest.flatMap(request -> otpService.otpValidation(request, "ADM"));
    }

  /**
   * Find by email mono.
   *
   * @param email the email
   * @return the mono
   */
  public Mono<AdminAccount> findByEmail(String email) {
        return adminAccountDomainService.findByEmail(email)
                .switchIfEmpty(Mono.error( new UnauthorizedException(INVALID_USER)));
    }

//    public Mono<SignUpResponse> signUp(Mono<SignUpRequest> signUpRequest) {
//        return signUpRequest.map(
//                request -> {
//                    request.setPassword(passwordEncoder.encode(request.getPassword()));
//                    return accountMapper.requestToEntity(request);
//                }
//        ).map(accountMapper::entityToResponse).doOnSuccess(u -> log.info("Created new user with ID = " + u.getEmail()));
//
//    }

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
                    if (account.getStatus().equals("9"))
                        return Mono.error(new UnauthorizedException(USER_ACCOUNT_DISABLE));

                    //if (!passwordEncoder.encode(password).equals(account.getPassword()))
                    log.debug("password => {}", password);
                    if (!passwordEncoder.matches(password, account.getPassword()))
                    //if  (!password.equals(account.getPassword()))
                        return Mono.error(new UnauthorizedException(INVALID_USER_PASSWORD));

                    return generateTokenOne(account, TokenType.ACCESS)
                            .map(result -> {
                                log.debug("generateToken => {}", result);
                                result.setEmail(account.getEmail());
                                result.setOtpInfo(otpService.generate(account.getEmail(), account.getOtpSecretKey()));

                                if (StringUtils.isEmpty(account.getOtpSecretKey())) {
                                    // otp_secret_key 등록.
                                    log.debug("otp secret key is null => save data");
                                    account.setOtpSecretKey(result.getOtpInfo().getEncodeKey());
                                    account.setLastLoginDate(LocalDateTime.now());
                                    adminAccountDomainService.save(account).then().log("result completed...").subscribe();
                                }
                                return result;
                            });
                })
                .switchIfEmpty(Mono.error(new UnauthorizedException(INVALID_TOKEN)));
    }

  /**
   * 1차 토큰 생성
   *
   * @param account   the account
   * @param tokenType the token type
   * @return mono mono
   */
  public Mono<TokenOtpInfo> generateTokenOne(AdminAccount account, TokenType tokenType) {

        log.debug("generateTokenOne create......{} {}", account.getId(), tokenType);
        return adminAccessDomainService.findByAdminId(account.getId())
                .flatMap(result -> {
                    log.debug("admin_access data => {}", result);
                  return roleManagementDomainService.findFirstRole(result.getRoles()).flatMap(roleManagement -> {
                    GenerateTokenInfo generateTokenInfo = GenerateTokenInfo
                        .builder()
                        .secret(jwtProperties.getSecret())
                        .expiration(jwtProperties.getExpiration().get(TokenType.ACCESS.getValue()))
                        .subject(roleManagement.getSiteId())  // request.getClientId())
                        .issuer(account.getEmail())
                        .claims(Map.of("ROLE", result.getRoles(), "account_id", account.getId()))  // 지금은 인증
                        .build();

                    return Mono.just(generateOtp(generateTokenInfo)
                        .toBuilder()
                        .siteId(roleManagement.getSiteId())
                        .build());
                  }).publishOn(Schedulers.boundedElastic()).doOnNext(tokenOtpInfo ->
                      redisTemplateSample.saveToken(account.getEmail()+"::OTP", tokenOtpInfo.toString())
                      .log("result ->save success..")
                      .subscribe()).flatMap(Mono::just);
                })
                .switchIfEmpty(Mono.error(new UnauthorizedException(INVALID_TOKEN)));
    }

}
