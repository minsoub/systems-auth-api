package com.bithumbsystems.auth.api.init;

import com.bithumbsystems.auth.data.mongodb.client.entity.RsaCipherInfo;
import com.bithumbsystems.auth.service.AuthService;
import javax.annotation.PostConstruct;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Component;
import reactor.core.publisher.Mono;

@Slf4j
@Component
@RequiredArgsConstructor
public class InitialSetting {

  private final AuthService authService;

  @PostConstruct
  public void setInitialData() {
    log.debug(">>> start setInitialData");
    Mono<RsaCipherInfo> rsaCipherInfoMono = authService.createRsaCipherCache();
    log.debug(">>> RsaCipherInfo : {}", rsaCipherInfoMono.block().toString());
    log.debug(">>> end setInitialData");
  }
}
