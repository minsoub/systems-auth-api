package com.bithumbsystems.auth.data.mongodb.client.entity;

import com.bithumbsystems.auth.data.mongodb.client.enums.Status;
import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.Getter;
import lombok.Setter;
import org.springframework.data.annotation.Id;
import org.springframework.data.mongodb.core.mapping.Document;
import org.springframework.data.mongodb.core.mapping.FieldType;
import org.springframework.data.mongodb.core.mapping.MongoId;

import java.time.LocalDateTime;

@Document(collection = "admin_account")
@AllArgsConstructor
@Getter
@Setter
@Data
public class AdminAccount {
    @MongoId(value = FieldType.STRING, targetType = FieldType.STRING)
    private String id;
    private String name;
    private String email;
    private String password;
    private String oldPassword;
    private String otpSecretKey;
    private Status status;
    private Boolean isUse;
    private Long loginFailCount;
    private LocalDateTime lastLoginDate;
    private LocalDateTime lastPasswordUpdateDate;
    private LocalDateTime createDate;
    private String createAdminAccountId;
    private LocalDateTime updateDate;
    private String updateAdminAccountId;
}
