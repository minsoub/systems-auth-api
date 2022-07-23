package com.bithumbsystems.auth.core.model.response.token;

import java.util.Date;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class TokenResponse {
    private String email;
    private Date issuedAt;
    private Date accessExpiresAt;
    private Date refreshExpiresAt;
    private String accessToken;
    private String refreshToken;
}