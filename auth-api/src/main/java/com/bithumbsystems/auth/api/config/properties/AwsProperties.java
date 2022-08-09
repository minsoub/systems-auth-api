package com.bithumbsystems.auth.api.config.properties;

import lombok.Getter;
import lombok.Setter;
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

  @Value("${cloud.aws.param-store.kms-name}")
  private String paramStoreKmsName;

  @Value("${cloud.aws.param-store.crypto-name}")
  private String paramStoreCryptoName;

  @Value("${cloud.aws.param-store.lrc-name}")
  private String paramStoreLrcName;

  @Value("${cloud.aws.param-store.message-name}")
  private String paramStoreMessageName;
  @Value("${cloud.aws.param-store.auth-name}")
  private String paramStoreAuthName;
  @Setter
  private String emailSender;
}
