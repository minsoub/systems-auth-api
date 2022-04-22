package com.bithumbsystems.auth.data.mongodb.entity;

import lombok.AllArgsConstructor;
import lombok.Getter;
import lombok.Setter;
import org.springframework.data.annotation.Id;
import org.springframework.data.mongodb.core.mapping.Document;

import java.util.List;

@Document(collection = "accounts")
@AllArgsConstructor
@Getter
@Setter
public class Account {
    @Id
    private String id;
    private String password;
    private String email;
    private boolean isEnabled;
    private List<String> roles;
}
