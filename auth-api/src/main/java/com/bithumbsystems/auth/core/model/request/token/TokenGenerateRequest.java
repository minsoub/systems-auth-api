package com.bithumbsystems.auth.core.model.request.token;

import com.bithumbsystems.auth.data.mongodb.client.enums.Status;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class TokenGenerateRequest {
  Status status;
  String siteId;
  String email;
  Object roles;
  String accountId;
}
