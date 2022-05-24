package com.bithumbsystems.auth.api.config.property;

import lombok.Getter;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Configuration;

@Configuration
@Getter
public class AwsProperties {

  @Value("${cloud.aws.region.static}")
  private String region;

  @Value("${cloud.aws.param-store.prefix}")
  private String prefix;

  @Value("${cloud.aws.param-store.doc-name}")
  private String paramStoreDocName;

  @Value("${cloud.aws.param-store.redis-name}")
  private String paramStoreRedisName;

}
