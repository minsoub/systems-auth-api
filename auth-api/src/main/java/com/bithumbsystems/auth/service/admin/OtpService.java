package com.bithumbsystems.auth.service.admin;

import static com.bithumbsystems.auth.core.model.enums.ErrorCode.INVALID_OTP_NUMBER;

import com.bithumbsystems.auth.api.config.AwsConfig;
import com.bithumbsystems.auth.api.config.properties.JwtProperties;
import com.bithumbsystems.auth.api.exception.authorization.UnauthorizedException;
import com.bithumbsystems.auth.core.model.auth.TokenInfo;
import com.bithumbsystems.auth.core.model.request.OtpRequest;
import com.bithumbsystems.auth.core.model.request.token.TokenGenerateRequest;
import com.bithumbsystems.auth.core.model.response.OtpResponse;
import com.bithumbsystems.auth.core.util.AES256Util;
import com.bithumbsystems.auth.core.util.JwtVerifyUtil;
import com.bithumbsystems.auth.data.authentication.entity.AdminAccount;
import com.bithumbsystems.auth.data.authentication.enums.Status;
import com.bithumbsystems.auth.data.authentication.service.AdminAccountDomainService;
import com.bithumbsystems.auth.data.redis.entity.OtpHistory;
import com.bithumbsystems.auth.data.redis.service.OtpHistoryDomainService;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.time.LocalDateTime;
import java.util.Arrays;
import java.util.Date;
import java.util.Optional;
import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.apache.commons.codec.binary.Base32;
import org.apache.commons.lang3.StringUtils;
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
                    .flatMap(result -> {
                      // success token validation check
                      // otp validation check
                      log.debug("jwt validation check completed : {}", result);
                      if (otpCheckCode(request.getOtpNo(),
                          encodeKey)) { // request.getEncodeKey())) {
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

                          // 사용자 encodeKey 저장.
                          adminAccountDomainService.findById(
                                  result.claims.get("account_id").toString())
                              .publishOn(Schedulers.boundedElastic())
                              .map(account -> {
                                account.setOtpSecretKey(encodeKey); // request.getEncodeKey());
                                account.setLastLoginDate(LocalDateTime.now());
                                account.setLoginFailCount(0L);
                                if (!needPasswordChange(account)) {
                                  account.setStatus(Status.NORMAL);
                                }
                                adminAccountDomainService.save(account).then()
                                    .subscribe();
                                return account;
                              }).subscribe();
                        }).flatMap(Mono::just);
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

    // 1번 사용했던 OTP 번호 재시도 시 오류 처리(보안취약점 - 자동화공격 방지)
    if (otpHistoryOptional.isPresent()) {
      return Mono.error(new UnauthorizedException(INVALID_OTP_NUMBER));
    }
    return Mono.empty();
  }

  private static boolean needPasswordChange(AdminAccount account) {
    return account.getStatus() == Status.INIT_REQUEST
        || account.getStatus() == Status.CHANGE_PASSWORD || account.getLastLoginDate() == null
        || account.getLastPasswordUpdateDate() == null;
  }


  /**
   * QR 코드를 생성해서 리턴한다. (최초 생성)
   *
   * @param email        the email
   * @param optSecretKey the opt secret key
   * @return otp response
   */
  public OtpResponse generate(String email, String optSecretKey) {
    byte[] buffer = new byte[5 + 5 * 5];
    new SecureRandom().nextBytes(buffer);
    Base32 codec = new Base32();
    byte[] secretKey = Arrays.copyOf(buffer, 10);
    byte[] bEncodedKey = codec.encode(secretKey);

    String encodedKey = StringUtils.isEmpty(optSecretKey) ? new String(bEncodedKey) : optSecretKey;
    String[] arrData = email.split("@");
    String url = getQRBarcodeURL(arrData[0], arrData[1], encodedKey);

    OtpResponse res = OtpResponse.builder()
        .encodeKey(AES256Util.encryptAES(config.getCryptoKey(), encodedKey)).url(url).build();

    log.debug("OptResponse generate => {}", res);

    return res;
  }

  private boolean otpCheckCode(String userDigit, String optKey) {
    log.debug("otpCheckCode => {}, {}", userDigit, optKey);
    long optNum = Integer.parseInt(userDigit);    // 6 digit
    long wave = new Date().getTime() / 30000;    // Google OTP 주기는 30sec
    boolean result = false;

    try {
      Base32 codec = new Base32();
      byte[] decodeKey = codec.decode(optKey);
      int window = 3;
      for (int i = -window; i <= window; ++i) {
        long hash = verifyCode(decodeKey, wave + i);
        if (hash == optNum) {
          result = true;
        }
      }
    } catch (InvalidKeyException | NoSuchAlgorithmException e) {
      log.debug("Key Exception  => {}", e.getMessage());
      return false;
    }
    return result;
  }

  private int verifyCode(byte[] key, long t) throws NoSuchAlgorithmException, InvalidKeyException {
    byte[] data = new byte[8];
    long value = t;
    for (int i = 8; i-- > 0; value >>>= 8) {
      data[i] = (byte) value;
    }
    SecretKeySpec signKey = new SecretKeySpec(key, "HmacSHA1");
    Mac mac = Mac.getInstance("HmacSHA1");
    mac.init(signKey);
    byte[] hash = mac.doFinal(data);

    int offset = hash[20 - 1] & 0xF;

    long truncatedHash = 0;
    for (int i = 0; i < 4; ++i) {
      truncatedHash <<= 8;
      truncatedHash |= (hash[offset + i] & 0xFF);
    }
    truncatedHash &= 0x7FFFFFFF;
    truncatedHash %= 1000000;

    return (int) truncatedHash;
  }

  /**
   * QR 코드 주소 생성
   *
   * @param user
   * @param host
   * @param secret
   * @return
   */
  private String getQRBarcodeURL(String user, String host, String secret) {
    String format2 = "https://chart.apis.google.com/chart?cht=qr&chs=200x200&chl=otpauth://totp/%s@%s%%3Fsecret%%3D%s&chld=H|0";

    return String.format(format2, user, host, secret);
  }
}
