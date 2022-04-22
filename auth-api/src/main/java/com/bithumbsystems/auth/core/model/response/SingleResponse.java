package com.bithumbsystems.auth.core.model.response;

import com.bithumbsystems.auth.core.model.enums.ReturnCode;
import lombok.AllArgsConstructor;
import lombok.Getter;

@AllArgsConstructor
@Getter
public class SingleResponse<T> {
    private ReturnCode status;
    private T data;
}
