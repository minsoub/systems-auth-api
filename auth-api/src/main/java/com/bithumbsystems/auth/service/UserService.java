package com.bithumbsystems.auth.service;


import static com.bithumbsystems.auth.core.model.enums.ErrorCode.*;
import static com.bithumbsystems.auth.core.util.JwtGenerateUtil.generateOtp;

import com.bithumbsystems.auth.api.config.AwsConfig;
import com.bithumbsystems.auth.api.config.property.JwtProperties;
import com.bithumbsystems.auth.api.exception.ErrorData;
import com.bithumbsystems.auth.api.exception.authorization.UnauthorizedException;
import com.bithumbsystems.auth.core.model.auth.GenerateTokenInfo;
import com.bithumbsystems.auth.core.model.auth.TokenInfo;
import com.bithumbsystems.auth.core.model.auth.TokenOtpInfo;
import com.bithumbsystems.auth.core.model.enums.ResultCode;
import com.bithumbsystems.auth.core.model.enums.TokenType;
import com.bithumbsystems.auth.core.model.request.OtpRequest;
import com.bithumbsystems.auth.core.model.request.UserCaptchaRequest;
import com.bithumbsystems.auth.core.model.request.UserJoinRequest;
import com.bithumbsystems.auth.core.model.request.UserRequest;
import com.bithumbsystems.auth.core.model.response.SingleResponse;
import com.bithumbsystems.auth.core.util.AES256Util;
import com.bithumbsystems.auth.data.mongodb.client.entity.UserAccount;
import com.bithumbsystems.auth.data.mongodb.client.service.UserAccountDomainService;
import com.bithumbsystems.auth.data.redis.RedisTemplateSample;
import java.time.LocalDateTime;
import java.util.Map;
import lombok.RequiredArgsConstructor;
import lombok.extern.log4j.Log4j2;
import org.apache.commons.lang3.StringUtils;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import reactor.core.publisher.Mono;

@Service
@Log4j2
@RequiredArgsConstructor
public class UserService {
    private final OtpService otpService;
    private final JwtProperties jwtProperties;
    private final UserAccountDomainService userAccountDomainService;
    private final RedisTemplateSample redisTemplateSample;
    private final AwsConfig config;

    private final PasswordEncoder passwordEncoder;

    private final CaptchaService captchaService;

    /**
     * 일반 사용자 로그인 처리 - 1차 로그인
     * @param userRequest
     * @return
     */
    public Mono<TokenOtpInfo> userLogin(Mono<UserRequest> userRequest) {
        return userRequest.flatMap(request -> authenticateUser(
                AES256Util.decryptAES(AES256Util.CLIENT_AES_KEY_LRC, request.getEmail())
                , AES256Util.decryptAES(AES256Util.CLIENT_AES_KEY_LRC, request.getPasswd())
                , request.getSiteId()
                )
        );
    }

    /**
     * 일반 사용자 로그인 처리 - 1차 로그인 with captcha
     * @param userCaptchaRequest
     * @return
     */
    public Mono<TokenOtpInfo> userCaptchaLogin(Mono<UserCaptchaRequest> userCaptchaRequest) {
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
     * 일반 사용자 2차 로그인 (otp 로그인)
     *
     * @param otpRequest
     * @return
     */
    public Mono<TokenInfo> userOtp(Mono<OtpRequest> otpRequest) {
        return otpRequest.flatMap(request -> otpService.otpValidation(request, "USR"));
    }

    /**
     * 사용자 가입을 처리한다.
     *
     * @param joinRequest
     * @return
     */
    public Mono<SingleResponse> join(Mono<UserJoinRequest> joinRequest) {
        log.debug("join called...");
        return joinRequest.flatMap(req -> {
           //String encryptEmail = config.encryptAes256(req.getEmail());  // Mono.defer(() ->Mono.just(config.encrypt(req.getEmail())));
            String encryptEmail = AES256Util.encryptAES(config.getKmsKey(), req.getEmail(), true);
            return Mono.defer(() -> userAccountDomainService.findByEmail(encryptEmail)   // config.encrypt(req.getEmail()))
                        .map(result -> {
                            log.debug("join method fail result => {}", result);
                            ErrorData error = new ErrorData(EXISTED_USER);
                            SingleResponse res = new SingleResponse(error, ResultCode.ERROR);
                            return res;
                        })
                        .switchIfEmpty(Mono.defer(() ->userRegister(req))));
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
                    .status("NORMAL")
                    .createDate(LocalDateTime.now())
                    .createAccountId("admin")
                    .build();

            log.debug("user account data : {}", user);
            return userAccountDomainService.save(user)
                    .map(r -> {
                        SingleResponse res = new SingleResponse("가입을 완료하였습니다!!!");
                        log.debug("success => {}", res);
                        return res;
                    });
    }

    /**
     * 1차 인증 후 사용자 Otp 생성
     *
     * @param email
     * @param password
     * @param clientId
     * @return
     */
    private Mono<TokenOtpInfo> authenticateUser(String email, String password, String clientId) {
        return userAccountDomainService.findByEmail(AES256Util.encryptAES(config.getKmsKey(), email, true))
                .flatMap(account -> {
                    log.debug("result account data => {}", account);
                    if (account.getStatus().equals("9"))
                        return Mono.error(new UnauthorizedException(USER_ACCOUNT_DISABLE));

                    if (!passwordEncoder.matches(password, account.getPassword())) {
                        return Mono.error(new UnauthorizedException(INVALID_USER_PASSWORD));
                    }

                    return generateTokenOne(account, TokenType.ACCESS, clientId)
                            .map(result -> {
                                log.debug("generateToken => {}", result);
                                result.setId(account.getId());
                                result.setEmail(email);  // account.getEmail());
                                result.setOtpInfo(otpService.generate(email, account.getOtpSecretKey()));  // account.getEmail(), account.getOtp_secret_key()));

                                if (StringUtils.isEmpty(account.getOtpSecretKey())) {
                                    // otp_secret_key 등록.
                                    log.debug("otp secret key is null => save data");
                                    account.setOtpSecretKey(result.getOtpInfo().getEncodeKey());
                                    account.setLastLoginDate(LocalDateTime.now());
                                    userAccountDomainService.save(account).then().log("result completed...").subscribe();
                                }
                                return result;
                            });
                })
                .switchIfEmpty(Mono.error(new UnauthorizedException(INVALID_USERNAME)));
    }


    /**
     * 1차 토큰 생성
     * @param account
     * @param tokenType
     * @return
     */
    private Mono<TokenOtpInfo> generateTokenOne(UserAccount account, TokenType tokenType, String clientId) {

        log.debug("generateTokenOne create......{}", account.getId());
        return userAccountDomainService.findById(account.getId())
                .map(result -> {
                    log.debug("admin_access data => {}", result);
                    GenerateTokenInfo generateTokenInfo = GenerateTokenInfo
                        .builder()
                        .secret(jwtProperties.getSecret())
                        .expiration(jwtProperties.getExpiration().get(TokenType.ACCESS.getValue()))
                        .subject(clientId)  // request.getClientId())
                        .issuer(account.getEmail())
                            .claims(Map.of("ROLE", "USER", "account_id", account.getId()))  // 지금은 인증

                            .build();

                    var tokenInfo = generateOtp(generateTokenInfo)
                        .toBuilder()
                        .siteId(clientId)
                        .build();
                    redisTemplateSample.saveToken(account.getEmail()+"::OTP", tokenInfo.toString()).log("result ->save success..").subscribe();
                    return tokenInfo;
                })
                .switchIfEmpty(Mono.error(new UnauthorizedException(INVALID_USERNAME)));
    }


}
