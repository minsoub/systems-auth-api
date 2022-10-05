package com.bithumbsystems.auth.core.model.auth;

import com.bithumbsystems.auth.data.authentication.enums.Status;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

import java.util.Date;

@Data
@Builder(toBuilder = true)
@NoArgsConstructor
@AllArgsConstructor
public class TokenInfo {
    private String accessToken;
    private String refreshToken;
    private Date issuedAt;
    private Date expiresAt;
    private Date refreshExpiresAt;
    private Status status;
}
