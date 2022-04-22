package com.bithumbsystems.auth.api.exception;

import com.bithumbsystems.auth.core.model.response.ErrorResponse;
import lombok.Getter;
import lombok.Setter;
import org.springframework.boot.web.error.ErrorAttributeOptions;
import org.springframework.boot.web.reactive.error.DefaultErrorAttributes;
import org.springframework.stereotype.Component;
import org.springframework.web.reactive.function.server.ServerRequest;

import java.util.Map;

@Component
@Getter
@Setter
public class GlobalErrorAttributes extends DefaultErrorAttributes {

    private ErrorResponse errorResponse;

    @Override
    public Map<String, Object> getErrorAttributes(ServerRequest request,
                                                  ErrorAttributeOptions options) {
        Map<String, Object> map = super.getErrorAttributes(request, options);
        return map;
    }

}