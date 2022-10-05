package com.bithumbsystems.auth.data.authorization.entity;

import com.bithumbsystems.auth.data.authentication.enums.RoleType;
import java.time.LocalDateTime;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;
import lombok.ToString;
import org.springframework.data.mongodb.core.mapping.Document;
import org.springframework.data.mongodb.core.mapping.FieldType;
import org.springframework.data.mongodb.core.mapping.MongoId;

@Document(collection = "program")
@AllArgsConstructor
@Getter
@Setter
@Builder
@ToString
@NoArgsConstructor
public class Program {
  @MongoId(targetType = FieldType.STRING)
  private String id;
  private String name;
  private RoleType type;
  private String kindName;
  private String actionMethod;
  private String actionUrl;
  private Boolean isUse;
  private String description;
  private String siteId;
  private LocalDateTime createDate;
  private String createAdminAccountId;
  private LocalDateTime updateDate;
  private String updateAdminAccountId;
}
