package com.bithumbsystems.auth.data.mongodb.client.entity;

import java.time.LocalDateTime;
import java.util.UUID;
import lombok.Getter;
import org.springframework.data.annotation.Id;
import org.springframework.data.mongodb.core.mapping.Document;

@Document("client")
@Getter
public class Client {

  @Id
  private final UUID id;

  private final String secret;

  private final String jwtSecret;

  private final String jwtAccessTokenExpiration;

  private final String jwtRefreshTokenExpiration;

  private final String name;

  private final String isUse;

  private final String description;

  private final LocalDateTime createDate;

  public Client(String secret, String jwtSecret, String jwtAccessTokenExpiration,
      String jwtRefreshTokenExpiration, String name, String isUse, String description) {
    this.id = UUID.randomUUID();
    this.secret = secret;
    this.jwtSecret = jwtSecret;
    this.jwtAccessTokenExpiration = jwtAccessTokenExpiration;
    this.jwtRefreshTokenExpiration = jwtRefreshTokenExpiration;
    this.name = name;
    this.isUse = isUse;
    this.description = description;
    this.createDate = LocalDateTime.now();
  }
}

