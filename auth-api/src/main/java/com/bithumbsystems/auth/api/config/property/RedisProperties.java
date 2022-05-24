package com.bithumbsystems.auth.api.config.property;

import lombok.AllArgsConstructor;
import lombok.Getter;
import lombok.NoArgsConstructor;

@Getter
@NoArgsConstructor
@AllArgsConstructor
public class RedisProperties {

  String host;
  String port;
  String token;
}