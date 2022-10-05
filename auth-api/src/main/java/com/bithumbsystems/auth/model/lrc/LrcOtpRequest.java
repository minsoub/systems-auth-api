package com.bithumbsystems.auth.model.lrc;

import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;

@Data
@NoArgsConstructor
@AllArgsConstructor
public class LrcOtpRequest {
    String data1;   // email token
    String data2;   // otp data
    String otpNo;
}
