package com.bithumbsystems.auth.core.model.auth;

import lombok.*;

import java.security.Principal;

@AllArgsConstructor
@Getter
@Setter
public class UserPrincipal implements Principal {
    private String id;
    private String email;

    @Override
    public String getName() {
        return email;
    }
}
