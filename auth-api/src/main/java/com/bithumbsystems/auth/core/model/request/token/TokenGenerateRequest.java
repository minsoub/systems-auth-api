package com.bithumbsystems.auth.core.model.request.token;

import com.bithumbsystems.auth.data.mongodb.client.enums.Status;
import java.util.Map;
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
  String name;
  Object roles;
  String accountId;
  Map<String, Object> claims;
}
