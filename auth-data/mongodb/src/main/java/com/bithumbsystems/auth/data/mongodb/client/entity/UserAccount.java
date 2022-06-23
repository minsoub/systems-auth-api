package com.bithumbsystems.auth.data.mongodb.client.entity;

import java.time.LocalDateTime;
import lombok.Builder;
import lombok.Data;
import lombok.Getter;
import lombok.Setter;
import org.springframework.data.mongodb.core.mapping.Document;
import org.springframework.data.mongodb.core.mapping.FieldType;
import org.springframework.data.mongodb.core.mapping.MongoId;

@Document(collection = "lrc_user_account")
//@AllArgsConstructor
@Getter
@Setter
@Data
@Builder
public class UserAccount {
    @MongoId(value = FieldType.STRING, targetType = FieldType.STRING)
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
