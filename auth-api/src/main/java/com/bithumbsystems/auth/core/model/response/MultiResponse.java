package com.bithumbsystems.auth.core.model.response;

import com.bithumbsystems.auth.core.model.enums.ReturnCode;
import lombok.AllArgsConstructor;
import lombok.Getter;

import java.util.List;

@AllArgsConstructor
@Getter
public class MultiResponse<T> {
    private ReturnCode status;
    private List<T> data;
}
