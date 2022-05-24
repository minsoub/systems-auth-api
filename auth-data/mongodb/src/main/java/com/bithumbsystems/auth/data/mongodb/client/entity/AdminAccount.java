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
    private String old_password;
    private String otp_secret_key;
    private String status;
    private LocalDateTime last_login_date;
    private LocalDateTime last_password_update_date;
    private LocalDateTime create_date;
    private String create_admin_account_id;
    private LocalDateTime update_date;
    private String update_admin_account_id;
}
