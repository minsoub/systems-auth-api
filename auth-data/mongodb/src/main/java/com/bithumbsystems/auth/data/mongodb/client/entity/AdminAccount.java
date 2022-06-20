package com.bithumbsystems.auth.data.mongodb.client.entity;

import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.Getter;
import lombok.Setter;
import org.springframework.data.annotation.Id;
import org.springframework.data.mongodb.core.mapping.Document;

import java.time.LocalDateTime;

@Document(collection = "admin_account")
@AllArgsConstructor
@Getter
@Setter
@Data
public class AdminAccount {
    @Id
    private String id;
    private String name;
    private String email;
    private String password;
    private String oldPassword;
    private String otpSecretKey;
    private String status;
    private Boolean isUse;
    private LocalDateTime lastLoginDate;
    private LocalDateTime lastPasswordUpdateDate;
    private LocalDateTime createDate;
    private String createAdminAccountId;
    private LocalDateTime updateDate;
    private String updateAdminAccountId;
}
