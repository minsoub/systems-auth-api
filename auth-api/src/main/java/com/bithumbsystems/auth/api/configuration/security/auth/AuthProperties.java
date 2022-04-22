package com.bithumbsystems.auth.api.configuration.security.auth;

import lombok.Getter;
import lombok.Setter;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.stereotype.Component;

import java.util.Map;

@Component
@ConfigurationProperties(prefix = "bithumbsystems.auth.jwt")
@Getter @Setter
public class AuthProperties {

    private String secret;

    private Map<String, String> expiration;
}
