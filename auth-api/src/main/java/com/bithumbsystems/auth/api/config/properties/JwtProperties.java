package com.bithumbsystems.auth.api.config.properties;

import lombok.Getter;
import lombok.Setter;
import org.springframework.context.annotation.Configuration;

@Configuration
@Getter @Setter
public class JwtProperties {

    private String secret;

    private String accessExpiration;

    private String refreshExpiration;

}
