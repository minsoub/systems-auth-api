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
    private LocalDateTime last_login_date;
    private String name;
    private String phone;
    private String sns_id;
    private String status;
    private String otp_secret_key;
    private LocalDateTime create_date;
    private String create_account_id;
    private LocalDateTime update_date;
    private String update_account_id;
}
