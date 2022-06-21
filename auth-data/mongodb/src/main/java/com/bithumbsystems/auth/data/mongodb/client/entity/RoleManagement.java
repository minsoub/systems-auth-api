package com.bithumbsystems.auth.data.mongodb.client.entity;

import com.bithumbsystems.auth.data.mongodb.client.enums.RoleType;
import java.time.LocalDate;
import java.time.LocalDateTime;
import lombok.Getter;
import lombok.Setter;
import lombok.ToString;
import org.springframework.data.mongodb.core.index.Indexed;
import org.springframework.data.mongodb.core.mapping.Document;
import org.springframework.data.mongodb.core.mapping.FieldType;
import org.springframework.data.mongodb.core.mapping.MongoId;

@Document(collection = "role_management")
@Getter
@Setter
@ToString
public class RoleManagement {
  @MongoId(targetType = FieldType.STRING)
  private String id;
  private String name;
  private RoleType type;
  private Boolean isUse;
  private LocalDate validStartDate;
  private LocalDate validEndDate;
  @Indexed
  private String siteId;
  private LocalDateTime createDate;
  private String createAdminAccountId;
  private LocalDateTime updateDate;
  private String updateAdminAccountId;
}
