package com.bithumbsystems.auth.core.model.request;

import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;

@Data
@NoArgsConstructor
@AllArgsConstructor
public class OtpRequest {
    String otp_no;
    String encode_key;
    String clientId;
    String token;
}
