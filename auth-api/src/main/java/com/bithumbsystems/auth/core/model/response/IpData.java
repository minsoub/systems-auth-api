package com.bithumbsystems.auth.core.model.response;

import lombok.*;

import java.time.LocalDate;

@Getter
@Setter
@AllArgsConstructor
@NoArgsConstructor
@Builder
public class IpData {
    private String id;
    private LocalDate validStartDate;
    private LocalDate validEndDate;
    private String allowIp;
}
