package com.bithumbsystems.auth.api.config.properties;

import lombok.Getter;
import lombok.Setter;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.boot.context.properties.ConfigurationPropertiesBinding;

import java.util.Map;

@ConfigurationPropertiesBinding
@ConfigurationProperties(prefix = "bithumbsystems.auth.jwt")
@Getter @Setter
public class JwtProperties {

    private String secret;

    private Map<String, String> expiration;
}
