package com.bithumbsystems.auth.api.init;

import com.bithumbsystems.auth.service.AuthService;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.context.event.ContextRefreshedEvent;
import org.springframework.context.event.EventListener;
import org.springframework.stereotype.Component;

@Slf4j
@Component
@RequiredArgsConstructor
public class InitialSetting {

  private final AuthService authService;

  @EventListener(ContextRefreshedEvent.class)
  public void setInitialData() {
    log.info(">>> start setInitialData");
    authService.createRsaCipherCache().subscribe();
    log.info(">>> end setInitialData");
  }
}
