package com.bithumbsystems.auth.core.model.response.token;

import com.bithumbsystems.auth.core.model.auth.TokenInfo;
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
    private TokenInfo accessToken;
    private TokenInfo refreshToken;
}