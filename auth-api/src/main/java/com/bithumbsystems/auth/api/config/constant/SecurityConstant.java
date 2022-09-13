package com.bithumbsystems.auth.api.config.constant;

import java.util.function.Function;
import java.util.function.Predicate;
import reactor.core.publisher.Mono;

public final class SecurityConstant {
  private static final String BEARER = "Bearer ";
  public static final Predicate<String> MATCH_BEARER_LENGTH = authValue -> authValue.length() > BEARER.length();
  public static final Function<String, Mono<String>> ISOLATE_BEARER_VALUE = authValue -> Mono.justOrEmpty(authValue.substring(BEARER.length()));

  public static final String SITE_ID = "site_id";
  public static final String LRC_SITE_ID = "62a15f4ae4129b518b133127";
  public static final String CPC_SITE_ID = "62a15f4ae4129b518b133128";
  public static final String MNG_SITE_ID = "62a15f4ae4129b518b133129";
}
