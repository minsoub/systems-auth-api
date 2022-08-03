package com.bithumbsystems.auth.core.util;

import java.nio.charset.StandardCharsets;
import lombok.extern.log4j.Log4j2;
import org.apache.commons.codec.binary.Base64;

import javax.crypto.Cipher;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.util.Arrays;

@Log4j2
public class AES256Util {

    public static final String CLIENT_AES_KEY_ADM = "fWISVCRBVpGh25HCS1U3a6bwqYewKUop";

    /**
     * Encrypt (AES)
     * @param keyString
     * @param plainText
     * @param bUrlSafe
     * @return
     */
    public static String encryptAES(String keyString, String plainText, boolean bUrlSafe) {
        String cipherText = "";
        if ((keyString == null) || keyString.length() == 0 || (plainText == null) || plainText.length() == 0) {
            throw new RuntimeException("Key is not found!");
        }

        // 키의 길이는 16, 24, 32 만 지원
        if ((keyString.length() != 16) && (keyString.length() != 24) && (keyString.length() != 32)) {
            throw new RuntimeException("Key is invalidate");
        }

        try {
            byte[] keyBytes = keyString.getBytes(StandardCharsets.UTF_8);
            byte[] plainTextBytes = plainText.getBytes(StandardCharsets.UTF_8);

            Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
            int bsize = cipher.getBlockSize();
            IvParameterSpec ivspec = new IvParameterSpec(Arrays.copyOfRange(keyBytes, 0, bsize));

            SecretKeySpec secureKey = new SecretKeySpec(keyBytes, "AES");
            cipher.init(Cipher.ENCRYPT_MODE, secureKey, ivspec);
            byte[] encrypted = cipher.doFinal(plainTextBytes);

            if (bUrlSafe) {
                cipherText = Base64.encodeBase64URLSafeString(encrypted);
            } else {
                cipherText = new String(Base64.encodeBase64(encrypted), StandardCharsets.UTF_8);
            }

        } catch (Exception e) {
            cipherText = "";
            e.printStackTrace();
        }

        log.debug("chipherTest => {}", cipherText);

        return cipherText;
    }


    /**
     * Decrypt (AES)
     * @param keyString
     * @param cipherText
     * @return
     */
    public static String decryptAES(String keyString, String cipherText) {
        String plainText = "";
        if ((keyString == null) || keyString.length() == 0 || (cipherText == null) || cipherText.length() == 0) {
            return plainText;
        }

        if ((keyString.length() != 16) && (keyString.length() != 24) && (keyString.length() != 32)) {
            return plainText;
        }

        try {
            byte[] keyBytes = keyString.getBytes(StandardCharsets.UTF_8);
            byte[] cipherTextBytes = Base64.decodeBase64(cipherText.getBytes(StandardCharsets.UTF_8));

            Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
            int bsize = cipher.getBlockSize();
            IvParameterSpec ivspec = new IvParameterSpec(Arrays.copyOfRange(keyBytes, 0, bsize));

            SecretKeySpec secureKey = new SecretKeySpec(keyBytes, "AES");
            cipher.init(Cipher.DECRYPT_MODE, secureKey, ivspec);
            byte[] decrypted = cipher.doFinal(cipherTextBytes);

            plainText = new String(decrypted, StandardCharsets.UTF_8);

        } catch (Exception e) {
            plainText = "";
            e.printStackTrace();
        }

        return plainText;
    }
}
