package com.bithumbsystems.auth.service;

import com.bithumbsystems.auth.api.config.property.JwtProperties;
import com.bithumbsystems.auth.api.exception.authorization.UnauthorizedException;

import com.bithumbsystems.auth.core.model.auth.GenerateTokenInfo;
import com.bithumbsystems.auth.core.model.auth.TokenInfo;
import com.bithumbsystems.auth.core.model.auth.TokenOtpInfo;
import com.bithumbsystems.auth.core.model.enums.TokenType;

import com.bithumbsystems.auth.core.model.request.OtpRequest;
import com.bithumbsystems.auth.core.model.request.UserRequest;
import com.bithumbsystems.auth.core.model.request.token.AuthRequest;

import com.bithumbsystems.auth.core.util.JwtVerifyUtil;
import com.bithumbsystems.auth.data.mongodb.client.entity.AdminAccount;
import com.bithumbsystems.auth.data.mongodb.client.service.AdminAccessDomainService;
import com.bithumbsystems.auth.data.mongodb.client.service.AdminAccountDomainService;
import com.bithumbsystems.auth.data.mongodb.client.service.ClientDomainService;

import com.bithumbsystems.auth.data.mongodb.client.service.UserAccountDomainService;
import com.bithumbsystems.auth.data.redis.RedisTemplateSample;

import lombok.RequiredArgsConstructor;
import lombok.extern.log4j.Log4j2;
import lombok.extern.slf4j.Slf4j;
import org.apache.commons.lang3.StringUtils;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import reactor.core.publisher.Mono;

import java.time.LocalDateTime;
import java.util.Map;

import static com.bithumbsystems.auth.core.model.enums.ErrorCode.*;
import static com.bithumbsystems.auth.core.util.JwtGenerateUtil.generate;
import static com.bithumbsystems.auth.core.util.JwtGenerateUtil.generateOtp;

@Service
@Log4j2
@RequiredArgsConstructor
public class AccountService {

    //private final AccountDomainService accountDomainService;
    private final AdminAccountDomainService adminAccountDomainService;
    private final AdminAccessDomainService adminAccessDomainService;
    private final UserAccountDomainService userAccountDomainService;

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
     * @param authRequest
     * @return
     */
    public Mono<TokenOtpInfo> login(Mono<AuthRequest> authRequest) {
        return authRequest.flatMap(request -> authenticate(request.getEmail(), request.getClientPassword()));
    }

    /**
     * 사용자 2차 로그인 (otp 로그인)
     *
     * @param otpRequest
     * @return
     */
    public Mono<TokenInfo> otp(Mono<OtpRequest> otpRequest) {
        return otpRequest.flatMap(request -> otpvalidation(request));
    }

    public Mono<AdminAccount> findByEmail(String email) {
        return adminAccountDomainService.findByEmail(email)
                .switchIfEmpty(Mono.error( new UnauthorizedException(INVALID_USERNAME)));
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
     * 사용자 인증 처리
     *
     * @param email
     * @param password
     * @return
     */
    public Mono<TokenOtpInfo> authenticate(String email, String password) {
        return findByEmail(email)
                .flatMap(account -> {
                    log.debug("result account data => {}", account);
                    if (account.getStatus().equals("9"))
                        return Mono.error(new UnauthorizedException(USER_ACCOUNT_DISABLE));

                    //if (!passwordEncoder.encode(password).equals(account.getPassword()))
                    if  (!password.equals(account.getPassword()))
                        return Mono.error(new UnauthorizedException(INVALID_USER_PASSWORD));

                    return generateTokenOne(account, TokenType.ACCESS)
                            .map(result -> {
                                log.debug("generateToken => {}", result);
                                result.setEmail(account.getEmail());
                                result.setOtpInfo(otpService.generate(account.getEmail(), account.getOtp_secret_key()));

                                if (StringUtils.isEmpty(account.getOtp_secret_key())) {
                                    // otp_secret_key 등록.
                                    log.debug("otp secret key is null => save data");
                                    account.setOtp_secret_key(result.getOtpInfo().getEncode_key());
                                    account.setLast_login_date(LocalDateTime.now());
                                    adminAccountDomainService.save(account).then().log("result completed...").subscribe();
                                }
                                return result;
                            });
                })
                .switchIfEmpty(Mono.error(new UnauthorizedException(INVALID_USERNAME)));
    }

    /**
     * OTP 처리
     * 처리완료 후 토큰정보를 리턴한다.
     *
     * @param request
     * @return
     */
    public Mono<TokenInfo> otpvalidation(OtpRequest request) {
        // Token Validation check and otp no check
        log.debug("otp validation check start => {}", request);
        return JwtVerifyUtil.check(request.getToken(), jwtProperties.getSecret())
                .flatMap(result -> {
                    // success token validation check
                    // otp validation check
                    log.debug("jwt validation check completed : {}", result);
                    if (otpService.otpCheckCode(request.getOtp_no(), request.getEncode_key())) {
                        // 2차 토큰 생성
                        return generateToken(request, result.claims.getIssuer());

                    }else {
                        return Mono.error(new UnauthorizedException(INVALID_OTP_NUMER));
                    }
                });
    }

    /**
     * 2차 인증에 대한 토큰 생성 및 저장
     *
     * @param request
     * @param email
     * @return
     */
    public Mono<TokenInfo> generateToken(OtpRequest request, String email) {
        log.debug("generateToken create......{}", request);

        log.debug("admin_access data => {}", request);
        GenerateTokenInfo generateTokenInfo = GenerateTokenInfo
                .builder()
                .secret(jwtProperties.getSecret())
                .expiration(jwtProperties.getExpiration().get(TokenType.ACCESS.getValue()))
                .subject( request.getClientId())  // request.getClientId())
                .issuer(email)
                .claims(Map.of("ROLE", "OTP"))  // 지금은 인증
                .build();
        var tokenInfo = generate(generateTokenInfo)
                .toBuilder()
                .build();
        return redisTemplateSample.saveToken(email, tokenInfo.toString())  // .getAccessToken())
                .map(result -> tokenInfo);

    }
    /**
     * 1차 토큰 생성
     * @param account
     * @param tokenType
     * @return
     */
    public Mono<TokenOtpInfo> generateTokenOne(AdminAccount account, TokenType tokenType) {

        log.debug("generateTokenOne create......{}", account.getId());
        return adminAccessDomainService.findByAdminId(account.getId())
                .map(result -> {
                    log.debug("admin_access data => {}", result);
                    GenerateTokenInfo generateTokenInfo = GenerateTokenInfo
                            .builder()
                            .secret(jwtProperties.getSecret())
                            .expiration(jwtProperties.getExpiration().get(TokenType.ACCESS.getValue()))
                            .subject( result.getSite_id())  // request.getClientId())
                            .issuer(account.getEmail())
                            .claims(Map.of("ROLE", "OTP"))  // 지금은 인증
                            .build();

                    var tokenInfo = generateOtp(generateTokenInfo)
                            .toBuilder()
                            .clientId(result.getSite_id())
                            .build();
                    redisTemplateSample.saveToken(account.getEmail(), tokenInfo.toString()); // .getToken());
                    return tokenInfo;
                })
                .switchIfEmpty(Mono.error(new UnauthorizedException(INVALID_USERNAME)));
    }

    /**
     * 일반 사용자 로그인 처리
     * @param userRequest
     * @return
     */
    public Mono<TokenInfo> userlogin(Mono<UserRequest> userRequest) {
        return userRequest.flatMap(request -> authenticateUser(request.getEmail(), request.getClientPassword(), request.getClientId()));
    }

    /**
     * 사용자 토큰 생성
     *
     * @param email
     * @param password
     * @param clientId
     * @return
     */
    public Mono<TokenInfo> authenticateUser(String email, String password, String clientId) {
        return userAccountDomainService.findByEmail(email)
                .flatMap(account -> {
                    log.debug("result account data => {}", account);
                    if (account.getStatus().equals("9"))
                        return Mono.error(new UnauthorizedException(USER_ACCOUNT_DISABLE));

                    //if (!passwordEncoder.encode(password).equals(account.getPassword()))
                    if  (!password.equals(account.getPassword()))
                        return Mono.error(new UnauthorizedException(INVALID_USER_PASSWORD));

                    GenerateTokenInfo generateTokenInfo = GenerateTokenInfo
                            .builder()
                            .secret(jwtProperties.getSecret())
                            .expiration(jwtProperties.getExpiration().get(TokenType.ACCESS.getValue()))
                            .subject( clientId)
                            .issuer(email)
                            .claims(Map.of("ROLE", "USER"))  // 지금은 인증
                            .build();
                    var tokenInfo = generate(generateTokenInfo)
                            .toBuilder()
                            .build();
                    return redisTemplateSample.saveToken(email, tokenInfo.toString())  // .getAccessToken())
                            .map(result -> tokenInfo);
                })
                .switchIfEmpty(Mono.error(new UnauthorizedException(INVALID_USERNAME)));
    }
}
