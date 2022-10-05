package com.bithumbsystems.auth.data.authentication.entity;

import java.time.LocalDateTime;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;
import org.springframework.data.annotation.Id;
import org.springframework.data.mongodb.core.mapping.Document;

@Data
@Builder
@Document(collection = "rsa_cipher_info")
@NoArgsConstructor
@AllArgsConstructor
public class RsaCipherInfo {

  @Id private String id;

  private String serverPrivateKey;
  private String serverPublicKey;

  private LocalDateTime createdAt;
}
