package com.bithumbsystems.auth.core.model.response;

import com.bithumbsystems.auth.core.model.enums.ResultCode;
import java.util.List;
import lombok.Getter;

@Getter
public class MultiResponse<T> {
    private final ResultCode result;
    private final List<T> data;

    MultiResponse(List<T> data) {
        this.result = ResultCode.SUCCESS;
        this.data = data;
    }
}
