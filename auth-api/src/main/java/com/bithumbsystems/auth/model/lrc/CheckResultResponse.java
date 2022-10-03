package com.bithumbsystems.auth.model.lrc;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

@Builder
@Data
@AllArgsConstructor
@NoArgsConstructor
public class CheckResultResponse {
    private Boolean result;
}
