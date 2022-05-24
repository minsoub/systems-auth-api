package com.bithumbsystems.auth.service;

import com.bithumbsystems.auth.core.model.response.OtpResponse;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.apache.commons.codec.binary.Base32;
import org.springframework.stereotype.Service;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.util.Arrays;
import java.util.Date;
import java.util.Random;

@Service
@Slf4j
@RequiredArgsConstructor
public class OtpService {


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

        String encodedKey = opt_secret_key == null ? new String (bEncodedKey) : opt_secret_key;
        String[] arrData = email.split("@");
        String url = getQRBarcodeURL(arrData[0], arrData[1], encodedKey);

        //Mono<OtpResponse> res = Mono.just(OtpResponse.builder().encode_key(encodedKey).url(url).build());

        OtpResponse res = OtpResponse.builder().encode_key(encodedKey).url(url).build();

        log.debug("OptResponse generate => {}", res);

        return res;
    }

    public boolean otpCheckCode(String userDigit, String optKey) {
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
