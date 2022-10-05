package com.bithumbsystems.auth.core.model.request;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;
import org.springframework.http.HttpMethod;

@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class TokenValidationRequest {
    private String token;
    private HttpMethod method;
    private String requestUri;
    private String userIp;
    private String siteId;
    private String activeRole;
}
