package com.bithumbsystems.auth.core.model.response;

import com.bithumbsystems.auth.core.model.enums.ReturnCode;
import io.swagger.v3.oas.annotations.media.Schema;
import lombok.Getter;

@Getter
public class ErrorResponse {

    ErrorResponse() {
        this.result = ReturnCode.ERROR;
    }

    @Schema(description = "응답 결과", nullable = true)
    ReturnCode result;
}
