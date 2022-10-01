package com.bithumbsystems.auth.core.util;

import com.bithumbsystems.auth.core.model.response.OtpResponse;
import com.bithumbsystems.auth.data.mongodb.client.entity.AdminAccount;
import com.bithumbsystems.auth.data.mongodb.client.enums.Status;
import lombok.extern.slf4j.Slf4j;
import org.apache.commons.codec.binary.Base32;
import org.apache.commons.lang3.StringUtils;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.util.Arrays;
import java.util.Date;
@Slf4j
public class OtpUtil {

    public static boolean needPasswordChange(AdminAccount account) {
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
    public static OtpResponse generate(String email, String cryptoKey, String optSecretKey) {
        byte[] buffer = new byte[5 + 5 * 5];
        new SecureRandom().nextBytes(buffer);
        Base32 codec = new Base32();
        byte[] secretKey = Arrays.copyOf(buffer, 10);
        byte[] bEncodedKey = codec.encode(secretKey);

        String encodedKey = StringUtils.isEmpty(optSecretKey) ? new String(bEncodedKey) : optSecretKey;
        String[] arrData = email.split("@");
        String url = OtpUtil.getQRBarcodeURL(arrData[0], arrData[1], encodedKey);

        OtpResponse res = OtpResponse.builder()
                .encodeKey(AES256Util.encryptAES(cryptoKey, encodedKey)).url(url).build();

        log.debug("OptResponse generate => {}", res);

        return res;
    }

    public static boolean otpCheckCode(String userDigit, String optKey) {
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

    public static int verifyCode(byte[] key, long t) throws NoSuchAlgorithmException, InvalidKeyException {
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
    public static String getQRBarcodeURL(String user, String host, String secret) {
        String format2 = "https://chart.apis.google.com/chart?cht=qr&chs=200x200&chl=otpauth://totp/%s@%s%%3Fsecret%%3D%s&chld=H|0";
        return String.format(format2, user, host, secret);
    }
}
