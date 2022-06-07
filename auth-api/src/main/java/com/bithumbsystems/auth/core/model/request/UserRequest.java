package com.bithumbsystems.auth.core.model.request;


import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;

@Data
@NoArgsConstructor
@AllArgsConstructor
public class UserRequest {
    private String siteId;
    private String passwd;
    private String email;
}
