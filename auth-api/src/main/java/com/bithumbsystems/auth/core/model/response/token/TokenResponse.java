package com.bithumbsystems.auth.core.model.response.token;

import com.bithumbsystems.auth.data.mongodb.client.enums.Status;
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
    private String id;
    private String email;
    private Date issuedAt;
    private Date accessExpiresAt;
    private Date refreshExpiresAt;
    private String accessToken;
    private String refreshToken;
    private Status status;
}