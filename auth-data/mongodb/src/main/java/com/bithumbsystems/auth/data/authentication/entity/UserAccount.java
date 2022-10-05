package com.bithumbsystems.auth.data.authentication.entity;

import com.bithumbsystems.auth.data.authentication.enums.UserStatus;
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
    private UserStatus status;
    private String otpSecretKey;
    private Integer loginFailCount;
    private LocalDateTime loginFailDate;
    private LocalDateTime changePasswordDate;
    private LocalDateTime createDate;
    private String createAccountId;
    private LocalDateTime updateDate;
    private String updateAccountId;

    public void setLoginFail(Integer loginFailCount){
        this.loginFailCount = (loginFailCount == null)? 1 : loginFailCount;
        this.loginFailDate = LocalDateTime.now();
    }
}
