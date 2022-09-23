package com.bithumbsystems.auth.core.model.request;

import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;

@Data
@NoArgsConstructor
@AllArgsConstructor
public class AdminTempRequest {
    private String email;
    private String validData;
}
