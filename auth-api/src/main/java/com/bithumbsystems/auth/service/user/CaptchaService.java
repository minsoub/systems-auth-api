package com.bithumbsystems.auth.service.user;

import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.HttpHeaders;
import org.springframework.http.MediaType;
import org.springframework.stereotype.Service;
import org.springframework.web.reactive.function.BodyInserters;
import org.springframework.web.reactive.function.client.WebClient;
import reactor.core.publisher.Mono;

import java.util.Map;

/**
 * The type Captcha service.
 */
@Slf4j
@Service
public class CaptchaService {

  @Value("${google.recaptcha.secret.lrc}")
  private String secret;

  @Value("${google.recaptcha.verify.url}")
  private String googleRecaptchaVerifyUrl;

  private final WebClient webClient = WebClient.builder()
      .defaultHeader(HttpHeaders.CONTENT_TYPE, MediaType.APPLICATION_FORM_URLENCODED_VALUE)
      .build();

  /**
   * 구글 캡챠 인증 처리
   *
   * @param response the response
   * @return mono
   */
  public Mono<Boolean> doVerify(String response) {
    return webClient.post()
        .uri(googleRecaptchaVerifyUrl)
        .body(
            BodyInserters.fromFormData("secret", secret)
                .with("response", response)
        )
        .retrieve()
        .bodyToMono(Map.class)
        .map(resultMap -> {
          log.debug("===[doVerify]==========================================================");
          log.debug("#######################################################################");
          log.debug("resultMap:{}", resultMap);
          log.debug("resultMap-success:{}", resultMap.get("success"));
          log.debug("#######################################################################");
          log.debug("===[doVerify]==========================================================");
          if (resultMap != null && resultMap.containsKey("success") && resultMap.get("success") instanceof Boolean) {
            return (Boolean) resultMap.get("success");
          } else {
            return false;
          }
        });
  }
}
/*
    구글 캡챠 성공일 경우
    {
        "success": true,
        "challenge_ts": "2022-06-13T06:34:20Z",
        "hostname": "localhost"
    }

    구글 캡챠 실패일 경우
    {
        "success": false,
        "error-codes": [
            "timeout-or-duplicate"
        ]
    }
 */