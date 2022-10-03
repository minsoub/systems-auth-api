package com.bithumbsystems.auth.model.lrc;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

@Data
@Builder
@AllArgsConstructor
@NoArgsConstructor
public class ResetInfoResponse {
    private Boolean isExpire;
    private String validData;
}
