package com.bithumbsystems.auth.core.model.request;

import lombok.AllArgsConstructor;
import lombok.Data;

@AllArgsConstructor
@Data
public class ClientRegisterRequest {
  String secret;
  String jwtSecret;
  String jwtAccessTokenExpiration;
  String jwtRefreshTokenExpiration;
  String name;
  String isUse;
  String description;
}
