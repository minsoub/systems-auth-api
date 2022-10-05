package com.bithumbsystems.auth.data.authorization.entity;

import java.util.List;
import lombok.Builder;
import lombok.Data;

@Data
@Builder
public class AuthorizationResource {
  private String menuId;
  private Boolean visible;
  private List<String> programId;
}
