package com.bithumbsystems.auth.core.model.response;

import lombok.*;

import java.util.List;

@Getter
@Setter
@AllArgsConstructor
@NoArgsConstructor
@Builder
public class AccessIpResponse {
    private String userKey;
    private String siteId;
    private List<IpData> accessIpRequests;
}
