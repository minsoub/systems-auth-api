package com.bithumbsystems.auth.data.authentication.entity;

import java.time.LocalDateTime;
import java.util.Set;
import lombok.AllArgsConstructor;
import lombok.Getter;
import lombok.Setter;
import org.springframework.data.annotation.Id;
import org.springframework.data.mongodb.core.mapping.Document;
import org.springframework.data.mongodb.core.mapping.FieldType;
import org.springframework.data.mongodb.core.mapping.MongoId;

@Document(collection = "admin_access")
@AllArgsConstructor
@Getter
@Setter
public class AdminAccess {
    @MongoId(value = FieldType.STRING, targetType = FieldType.STRING)
    private String id;
    private String adminAccountId;
    private String name;
    private String email;
    private Boolean isUse;
    private Set<String> roles;
    private LocalDateTime lastLoginDate;
    private LocalDateTime createDate;
    private String createAdminAccountId;
    private LocalDateTime updateDate;
    private String updateAdminAccountId;
}
