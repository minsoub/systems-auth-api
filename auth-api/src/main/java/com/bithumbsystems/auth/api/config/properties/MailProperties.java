package com.bithumbsystems.auth.api.config.properties;

import lombok.Getter;
import lombok.Setter;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.boot.context.properties.ConfigurationPropertiesBinding;

@ConfigurationPropertiesBinding
@ConfigurationProperties(prefix = "mail")
@Getter
@Setter
public class MailProperties {
    private String logoUrl;
    private String loginUrl;
    private String confirmUrl;
}
