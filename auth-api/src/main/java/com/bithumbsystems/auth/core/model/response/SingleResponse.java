package com.bithumbsystems.auth.core.model.response;

import com.bithumbsystems.auth.core.model.enums.ResultCode;
import lombok.Getter;

@Getter
public class SingleResponse<T> {
    private final ResultCode result;
    private final T data;

    public SingleResponse(T data) {
        this.result = ResultCode.SUCCESS;
        this.data = data;
    }

    public SingleResponse(T data, ResultCode code) {
        this.result = code;
        this.data = data;
    }
}
