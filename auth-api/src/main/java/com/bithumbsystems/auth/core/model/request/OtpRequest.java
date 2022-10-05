package com.bithumbsystems.auth.core.model.request;

import com.bithumbsystems.auth.data.authentication.enums.Status;
import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;

@Data
@NoArgsConstructor
@AllArgsConstructor
public class OtpRequest {
    String otpNo;
    String name;
    String checkData;
    String siteId;
    String token;
    Status status;
}
