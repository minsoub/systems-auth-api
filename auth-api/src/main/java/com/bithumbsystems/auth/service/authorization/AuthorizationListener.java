package com.bithumbsystems.auth.service.authorization;

import com.bithumbsystems.auth.data.redis.AuthRedisService;
import io.awspring.cloud.messaging.listener.SqsMessageDeletionPolicy;
import io.awspring.cloud.messaging.listener.annotation.SqsListener;
import java.util.Map;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.messaging.handler.annotation.Headers;
import org.springframework.messaging.handler.annotation.Payload;
import org.springframework.stereotype.Component;

@Component
@Slf4j
@RequiredArgsConstructor
public class AuthorizationListener {

  private final AuthRedisService authRedisService;

  @SqsListener(value = {"${cloud.aws.sqs.authorization.queue-name}"}, deletionPolicy = SqsMessageDeletionPolicy.ON_SUCCESS)
  private void authorizationMessage(@Headers Map<String, String> header, @Payload String message) {
    log.debug("header: {} message: {}", header, message);
    log.debug("MessageGroupId: {}", header.get("MessageGroupId"));
    log.debug("message: {}", message);
    var role = header.get("MessageGroupId");
    authRedisService.delete("ROLE_" + role)
        .then(authRedisService.saveAuthorization("ROLE_" + header.get("MessageGroupId"), message))
        .subscribe();
  }
}