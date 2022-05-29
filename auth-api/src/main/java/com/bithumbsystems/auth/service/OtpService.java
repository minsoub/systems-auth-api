package com.bithumbsystems.auth.service;

import com.bithumbsystems.auth.api.config.property.JwtProperties;
import com.bithumbsystems.auth.api.exception.authorization.UnauthorizedException;
import com.bithumbsystems.auth.core.model.auth.GenerateTokenInfo;
import com.bithumbsystems.auth.core.model.auth.TokenInfo;
import com.bithumbsystems.auth.core.model.enums.TokenType;
import com.bithumbsystems.auth.core.model.request.OtpRequest;
import com.bithumbsystems.auth.core.model.response.OtpResponse;
import com.bithumbsystems.auth.core.util.JwtGenerateUtil;
import com.bithumbsystems.auth.core.util.JwtVerifyUtil;
import com.bithumbsystems.auth.data.redis.RedisTemplateSample;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.apache.commons.codec.binary.Base32;
import org.apache.commons.lang3.StringUtils;
import org.springframework.stereotype.Service;
import reactor.core.publisher.Mono;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.util.Arrays;
import java.util.Date;
import java.util.Map;
import java.util.Random;

import static com.bithumbsystems.auth.core.model.enums.ErrorCode.INVALID_OTP_NUMER;
import static com.bithumbsystems.auth.core.util.JwtGenerateUtil.generate;

@Service
@Slf4j
@RequiredArgsConstructor
public class OtpService {
    private final JwtProperties jwtProperties;
    private final RedisTemplateSample redisTemplateSample;
    /**
     * OTP 처리 - 2차
     * 처리완료 후 토큰정보를 리턴한다.
     *
     * @param request
     * @return
     */
    public Mono<TokenInfo> otpValidation(OtpRequest request, String userType) {
        // Token Validation check and otp no check
        log.debug("otp validation check start => {} : {}", userType, request);

        return JwtVerifyUtil.check(request.getToken(), jwtProperties.getSecret())
                .flatMap(result -> {
                    // success token validation check
                    // otp validation check
                    log.debug("jwt validation check completed : {}", result);
                    if (otpCheckCode(request.getOtp_no(), request.getEncode_key())) {
                        // 2차 토큰 생성
                        log.debug("2차 토큰 생성");
                        return generateToken(request, result.claims.getIssuer(), userType, result.claims.get("ROLE").toString());
                    }else {
                        log.debug("OTP check errror");
                        return Mono.error(new UnauthorizedException(INVALID_OTP_NUMER));
                    }
                });
    }

    /**
     * 2차 인증에 대한 토큰 생성 및 저장
     *
     * @param request
     * @param email
     * @param userType
     * @return
     */
    private Mono<TokenInfo> generateToken(OtpRequest request, String email, String userType, String role) {
        log.debug("generateToken create......{}", request);

        log.debug("admin_access data => {}", request);

        GenerateTokenInfo generateTokenInfo = GenerateTokenInfo
                .builder()
                .secret(jwtProperties.getSecret())
                .expiration(jwtProperties.getExpiration().get(TokenType.ACCESS.getValue()))
                .subject( request.getSite_id())  // request.getClientId())
                .issuer(email)
                .claims(Map.of("ROLE", role))  // 운영자에 대한 Role이 필요.
                .build();
        var tokenInfo = JwtGenerateUtil.generate(generateTokenInfo)
                .toBuilder()
                .build();
        return redisTemplateSample.saveToken(email, tokenInfo.toString())  // .getAccessToken())
                .map(result -> {
                    redisTemplateSample.deleteToken(email+"::OTP").log("delete otp token").subscribe();
                    return tokenInfo;
                });
    }

    /**
     * QR 코드를 생성해서 리턴한다. (최초 생성)
     *
     * @param email
     * @return
     */
    //public Mono<OtpResponse> generate(String email) {
    public OtpResponse generate(String email, String opt_secret_key) {
        byte[] buffer = new byte[5 + 5 * 5];
        new Random().nextBytes(buffer);
        Base32 codec = new Base32();
        byte[] secretKey = Arrays.copyOf(buffer, 10);
        byte[] bEncodedKey = codec.encode(secretKey);

        String encodedKey = StringUtils.isEmpty(opt_secret_key) ? new String (bEncodedKey) : opt_secret_key;
        String[] arrData = email.split("@");
        String url = getQRBarcodeURL(arrData[0], arrData[1], encodedKey);

        //Mono<OtpResponse> res = Mono.just(OtpResponse.builder().encode_key(encodedKey).url(url).build());

        OtpResponse res = OtpResponse.builder().encode_key(encodedKey).url(url).build();

        log.debug("OptResponse generate => {}", res);

        return res;
    }

    private boolean otpCheckCode(String userDigit, String optKey) {
        log.debug("otpCheckCode => {}, {}", userDigit, optKey);
        long optnum = Integer.parseInt(userDigit);    // 6 digit
        long wave = new Date().getTime() / 30000;    // Google OTP 주기는 30sec
        boolean result = false;

        try {
            Base32 codec = new Base32();
            byte[] decodeKey = codec.decode(optKey);
            int window = 3;
            for (int i= -window; i<= window; ++i) {
                long hash = verify_code(decodeKey, wave + i);
                if (hash == optnum) result = true;
            }
        }catch(InvalidKeyException | NoSuchAlgorithmException e) {
            log.debug("Key Exception  => {}", e);
            return false;
        }
        return result;
    }

    private int verify_code(byte[] key, long t) throws NoSuchAlgorithmException, InvalidKeyException {
        byte[] data = new byte[8];
        long value = t;
        for (int i=8; i-- > 0; value >>>= 8) {
            data[i] = (byte) value;
        }
        SecretKeySpec signKey = new SecretKeySpec(key, "HmacSHA1");
        Mac mac = Mac.getInstance("HmacSHA1");
        mac.init(signKey);
        byte[] hash = mac.doFinal(data);

        int offset = hash[20 - 1] & 0xF;

        long truncatedHash = 0;
        for (int i=0; i<4; ++i) {
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
        String format2 = "http://chart.apis.google.com/chart?cht=qr&chs=200x200&chl=otpauth://totp/%s@%s%%3Fsecret%%3D%s&chld=H|0";

        return String.format(format2, user, host, secret);
    }
}