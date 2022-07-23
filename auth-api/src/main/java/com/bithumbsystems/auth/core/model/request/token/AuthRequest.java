package com.bithumbsystems.auth.core.model.request.token;

import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;

@Data
@NoArgsConstructor
@AllArgsConstructor
public class AuthRequest {
    private String accessToken;
    private String refreshToken;
}
