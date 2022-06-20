package com.bithumbsystems.auth.core.model.request;


import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;

@Data
@NoArgsConstructor
@AllArgsConstructor
public class UserCaptchaRequest {
    private String siteId;
    private String passwd;
    private String email;
    private String captcha;
}
