package com.bithumbsystems.auth.api.config.datasource;

import lombok.RequiredArgsConstructor;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.Primary;
import org.springframework.context.annotation.Profile;
import org.springframework.data.redis.connection.ReactiveRedisConnectionFactory;
import org.springframework.data.redis.connection.RedisConfiguration;
import org.springframework.data.redis.connection.RedisPassword;
import org.springframework.data.redis.connection.RedisStandaloneConfiguration;
import org.springframework.data.redis.connection.lettuce.LettuceClientConfiguration;
import org.springframework.data.redis.connection.lettuce.LettuceConnectionFactory;
import org.springframework.data.redis.core.ReactiveStringRedisTemplate;

@Configuration
@RequiredArgsConstructor
@Profile("dev|prod")
public class RedisConfig {

  private final ParameterStoreConfig parameterStoreConfig;

  @Bean
  public RedisConfiguration defaultRedisConfig() {
    RedisStandaloneConfiguration config = new RedisStandaloneConfiguration();
    config.setHostName(parameterStoreConfig.getRedisProperties().getHost());
    config.setPort(Integer.parseInt(parameterStoreConfig.getRedisProperties().getPort()));
    config.setPassword(RedisPassword.of(parameterStoreConfig.getRedisProperties().getToken()));
    return config;
  }

  @Bean
  @Primary
  public ReactiveRedisConnectionFactory reactiveRedisConnectionFactory(RedisConfiguration defaultRedisConfig) {
    LettuceClientConfiguration clientConfig = LettuceClientConfiguration.builder()
        .useSsl().build();
    return new LettuceConnectionFactory(defaultRedisConfig, clientConfig);
  }

  @Primary
  @Bean
  ReactiveStringRedisTemplate reactiveRedisTemplate(@Qualifier("reactiveRedisConnectionFactory") ReactiveRedisConnectionFactory factory) {
    return new ReactiveStringRedisTemplate(factory);
  }
}
