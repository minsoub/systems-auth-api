package com.bithumbsystems.auth.service.authorization;

import com.bithumbsystems.auth.data.redis.AuthRedisService;
import io.awspring.cloud.messaging.listener.SqsMessageDeletionPolicy;
import io.awspring.cloud.messaging.listener.annotation.SqsListener;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.messaging.handler.annotation.Headers;
import org.springframework.messaging.handler.annotation.Payload;
import org.springframework.stereotype.Component;
import org.springframework.util.StringUtils;

import java.util.Map;

@Component
@Slf4j
@RequiredArgsConstructor
public class AccessIpRegisterListener {
    private final AuthRedisService authRedisService;

    @SqsListener(value = {"${cloud.aws.sqs.accessip.queue-name}"}, deletionPolicy = SqsMessageDeletionPolicy.ON_SUCCESS)
    private void accessIpRecevieMessage(@Headers Map<String, String> header, @Payload String message) {
        log.debug("header: {} message: {}", header, message);
        log.debug("MessageGroupId: {}", header.get("MessageGroupId"));
        log.debug("message: {}", message);
        var accessIpKey = header.get("MessageGroupId");
        if (StringUtils.hasLength(message) && message.equals("DELETE")) {
            authRedisService.delete(accessIpKey).subscribe();
        } else {
            authRedisService.delete(accessIpKey)
                    .then(authRedisService.saveAccessIpList(accessIpKey, message))
                    .subscribe();
        }
    }
}
