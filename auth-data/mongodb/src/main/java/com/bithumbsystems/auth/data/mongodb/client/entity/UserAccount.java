package com.bithumbsystems.auth.data.mongodb.client.entity;

import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.Getter;
import lombok.Setter;
import org.springframework.data.annotation.Id;
import org.springframework.data.mongodb.core.mapping.Document;

import java.time.LocalDateTime;

@Document(collection = "user_account")
@AllArgsConstructor
@Getter
@Setter
@Data
public class UserAccount {
    @Id
    private String id;
    private String email;
    private String password;
    private LocalDateTime last_login_date;
    private String name;
    private String phone;
    private String status;

    private LocalDateTime create_date;
    private String create_account_id;
    private LocalDateTime update_date;
    private String update_account_id;
}
