package com.bithumbsystems.auth.core.model.request;

import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;

@Data
@NoArgsConstructor
@AllArgsConstructor
public class OtpClearRequest {
    private String siteId;
    private String email;
    private String otpKey;
    private String token;
}