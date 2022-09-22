package com.bithumbsystems.auth.service.authorization;

import static org.junit.jupiter.api.Assertions.assertTrue;

import com.bithumbsystems.auth.service.cipher.RsaCipherService;
import java.io.UnsupportedEncodingException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.spec.InvalidKeySpecException;
import java.util.Map;
import javax.crypto.BadPaddingException;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

@DisplayName("RsaCipherService 테스트")
public class RsaCipherServiceTest {

  Logger log = LoggerFactory.getLogger(RsaCipherServiceTest.class);

  RsaCipherService rsaCipherService;

  @BeforeEach
  void setup() throws NoSuchAlgorithmException {
    rsaCipherService = new RsaCipherService();
  }

  @Test
  @DisplayName("01. AES Secret 및 iv 생성 테스트")
  void getRsaKeys() {

    Map<String, String> rsaKeys = rsaCipherService.getRsaKeys();

    log.debug("privateKey = {}", rsaKeys.get(RsaCipherService.PRIVATE_KEY_NAME));
    log.debug("publicKey = {}", rsaKeys.get(RsaCipherService.PUBLIC_KEY_NAME));

    assertTrue(rsaKeys.keySet().size() == 2);

  }

  @Test
  @DisplayName("02. AES 암호화 테스트")
  void encryptRSA()
      throws NoSuchPaddingException, NoSuchAlgorithmException, IllegalBlockSizeException, BadPaddingException, InvalidKeyException, InvalidKeySpecException {

    String plainText = "bithumb";
    String publicKey = "MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAh6LjqzlUTv3HzxFyOKRJUU1UrzuwDgT8xT+5FE2nfGr+zLWAOoy9WX9BTVNZ+ufs+CaGbC/jAntLJvQumi5DhM+x/FI/UYFz2QyqnyKwZUz23AGwRSZwK20JAUTYfoGn8z7m/UuHpyj2teQQyMf3M82MDs0RiwMKMuuAnE7Jb74YcsbLSemCdW1t6KsPmaBfIsKaP1CoW2CaCN90Q+bF/UCIxgncOjsKdulY3sj/40ahrlM7no3ovgz4I64CQRVPGVaHvCJMmzOCCHh4RnPotdGyUPF5z1JpeM5Prod00i9RU6O5Qv7Y36BmpXF1n68kRhaXQ/pQH9CR8Xp5YjGzjQIDAQAB";
    String encryptedText = rsaCipherService.encryptRSA(plainText, publicKey);

    log.debug("encryptedText = {}", encryptedText);

    assertTrue(encryptedText.length() > 10);
  }

  @Test
  @DisplayName("03. AES 복호화 테스트")
  void decryptRSA()
      throws NoSuchPaddingException, UnsupportedEncodingException, NoSuchAlgorithmException, IllegalBlockSizeException, BadPaddingException, InvalidKeyException, InvalidKeySpecException {

    String plainText = "This is a plain Text.";
    String privateKey = "MIIEvAIBADANBgkqhkiG9w0BAQEFAASCBKYwggSiAgEAAoIBAQCGooeYh9VmJHVwRWZ5sTkuozlz+Z/SamS0e3GLmPwtTWANCIV2jiJ/H6laSGjd0XJ7MUgUy+gDEPu/RGUn8bv/9ET+EUq6ORdihVnMumBQcaUftg2t3rovqON4e/VkqTyq5eee00sduHyEpjSLERG7ONjjgiVdY5YYmMjXb15vlw3iGdooiLFsnJ1us8CPBlO9xSeIH/EuPnnv2Ymi2X0+N8QVCqLh1mq7tdJvfLxCsJy95kWpv6UjPuJYh8sbeAon+hGX1UJDzRFNU6uk8fysfvCSc1PrOcNEXjHCN+aX0B7uhLSutW6ccRfQXA8FibaXDk/wcfF2+yFo9DwzolZJAgMBAAECggEAL0Wz/I99Ez8r6P7FK2dZn5F6I8l7H2Nx9pj9VjmiGbn4Rrs+OVFQtXgFe4i/IVtgKfc0yvCJh0IYUqEOL4dGLmmzK84ggeB34ITX8fViyfwNMWQ3y1vP3dob/Hrxv6VYgtz0haTE1CuptN2yxz14D1e3d7KDshW8ZuiGZHZbHyzVEJxUUlY7WYPgz+2Oo1fPl299JNp2QAXLdnPEEb3hWVgy1lb+psJ7qVjWO2IksXTRGMUNE2YkLxf4CpU77toSLE5Axpo9E4VdlRERFnldxBY85vWrNwu93UQbp9qufWxkZI/63F3xHqfSB5msNgoxGVLd68AoBzuZAl08LiszMQKBgQDC/qvu+cOOoBvtH28UifluVt4t7CFLOH4Z14MV7Y7icvqEENCXdP5TVjFaFrpjn+ymIhi5m4Dgf2mQVNEEWkbiz0iCeqI0Q7jqJXsXS0kdj+mpsTFwmSl0yFx5MoMH1hpWraDr2WXIBUoR0eRdBRGCDLtebL7krHjR7m4EfgD+HQKBgQCwwZI+MN3WUQXDgKu3s8PqhEs9PwmjhKcuxlIhMANbwapiqk3nLqoSv4Z0frbAxXWDlFvLZaREZe5zU/1e4OYGiMhgMJ+sOW9VTxaT+iJmTIseqRG220233IRz+bbHozTSbB4qFctj1UaWv9NKXQxbWaE3jSH1bIoStrKDAsoxHQKBgBk/rLem86F2LeeIWHPKYdfdu6sqli0NRZbHBxxBxGyiArozCy9xYLUdxgoqQzw/Kv9gDt+JuShYlyyvLtlnbyJTQMpUYshttHXtIIElqHQBfHoSjZpM2sdaYk73MWxEVui+VsXzQnCh7rNcADvjOh8i0ugpIJavln1oaCqAvlQpAoGAffJQLHRRfebZvoau1QUIstB1dDy4t4VMQy4ZU4CMxBLpP8iuHe7ITPef7N5lhlKs+4b5KaNRO1OOZysPvU1vWnSYosHC5MtAI39pTSPM4yvjbYN3Fd6KMFq3HpRuwy3t84oKrF4/QPG1jLE+8xv+NBFXqOetrN0cPV1lMakJPZkCgYBnc5qcK1utwug6MW0Iaf4wKC8J6fleAS/wc7BmMTjqD1ZJroU8VOeFQi24jXNjYuU80oks5x31r31C3g/pmnr6u8BABxlUfrSlv7ksjmJzLU7adMWglmOiimwZUZsooBFfGmRcacDtK3LWGUpyl6nj5naRJ2LzxYdk4vMO7W+bcQ==";
    String encryptedText = "UC2jYVPt7jwbBPYaIZiMfuZuSkGKyOutRmbNWzKRkRwOTMOaxD4CSwTgB7tRpTyvl+ntfgrY17VKbr6T5uHEOEwSQdoKIUyk9L4kvgR+DSwUmbXnmtf7gHtd+k1Ot8awmvlDdJerV0mCIxL6tIJ7WzwRHTez24urM/H0J3PBWyC5+D8bCqMLfloGgGWEWUzH9FVpFBAZRvJeXH2K2jlerVdic8OBJDY7V/FXsnBqJx4PHgsYI9P3VC1iiS4Txkhbbeo4prBa8VmlYqFx3Nnq2DM1pB++9f2hKK4q2846drlkIsHyTPPmPcyUys1937fEPwGJG27ew1m4iQ3UJr8BEw==";
    String decryptedText = rsaCipherService.decryptRSA(encryptedText, privateKey);

    log.debug("decryptedText = {}", decryptedText);

    assertTrue(plainText.equals(decryptedText));

  }
}
