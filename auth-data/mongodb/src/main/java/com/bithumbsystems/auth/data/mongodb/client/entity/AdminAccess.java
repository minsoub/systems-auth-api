package com.bithumbsystems.auth.data.mongodb.client.entity;

import lombok.AllArgsConstructor;
import lombok.Getter;
import lombok.Setter;
import org.springframework.data.annotation.Id;
import org.springframework.data.mongodb.core.mapping.Document;

import java.time.LocalDateTime;

@Document(collection = "admin_access")
@AllArgsConstructor
@Getter
@Setter
public class AdminAccess {
    @Id
    private String id;
    private String admin_account_id;
    private String name;
    private String email;
    private boolean is_use;
    private String role_management_id;
    private String site_id;
    private LocalDateTime create_date;
    private String create_admin_account_id;
    private LocalDateTime update_date;
    private String update_admin_account_id;
}
