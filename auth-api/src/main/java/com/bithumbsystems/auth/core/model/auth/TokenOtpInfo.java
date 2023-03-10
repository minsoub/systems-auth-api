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
public class TokenOtpInfo {
    private String siteId;
    private String email;
    private String name;
    private String token;
    private Date issuedAt;
    private Date expiresAt;
    //private OtpResponse otpInfo;
    private String validData;
    private String id;
    private Boolean isCode;
    private Status status;
}
