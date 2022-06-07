package com.bithumbsystems.auth.data.mongodb.client.entity;

import lombok.*;
import org.springframework.data.annotation.Id;
import org.springframework.data.mongodb.core.mapping.Document;

import java.time.LocalDateTime;

@Document(collection = "lrc_user_account")
//@AllArgsConstructor
@Getter
@Setter
@Data
@Builder
public class UserAccount {
    @Id
    private String id;
    private String email;
    private String password;
    private LocalDateTime lastLoginDate;
    private String name;
    private String phone;
    private String snsId;
    private String status;
    private String otpSecretKey;
    private LocalDateTime createDate;
    private String createAccountId;
    private LocalDateTime updateDate;
    private String updateAccountId;
}
