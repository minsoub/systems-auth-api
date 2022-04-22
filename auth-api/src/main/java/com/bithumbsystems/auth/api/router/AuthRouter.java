package com.bithumbsystems.auth.api.router;

import com.bithumbsystems.auth.api.handler.AuthHandler;
import com.bithumbsystems.auth.core.model.request.AuthRequest;
import com.bithumbsystems.auth.core.model.response.AuthResponse;
import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.Parameter;
import io.swagger.v3.oas.annotations.enums.ParameterIn;
import io.swagger.v3.oas.annotations.media.Content;
import io.swagger.v3.oas.annotations.media.Schema;
import io.swagger.v3.oas.annotations.parameters.RequestBody;
import io.swagger.v3.oas.annotations.responses.ApiResponse;
import lombok.RequiredArgsConstructor;
import org.springdoc.core.annotations.RouterOperation;
import org.springdoc.core.annotations.RouterOperations;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.MediaType;
import org.springframework.web.bind.annotation.RequestMethod;
import org.springframework.web.reactive.function.server.RouterFunction;
import org.springframework.web.reactive.function.server.RouterFunctions;

@Configuration
@RequiredArgsConstructor
public class AuthRouter {

    private final AuthHandler authHandler;

    @Bean
    @RouterOperations({
        @RouterOperation(
                path = "/auth/login",
                produces = {
                        MediaType.APPLICATION_JSON_VALUE
                },
                method = RequestMethod.POST,
                beanClass = AuthHandler.class,
                beanMethod = "login",
                operation = @Operation(
                        operationId = "login",
                        responses = {
                                @ApiResponse(
                                        responseCode = "200",
                                        description = "successful operation",
                                        content = @Content(schema = @Schema(
                                                implementation = AuthResponse.class
                                        ))
                                )
                        },
                        requestBody = @RequestBody(
                                content = @Content(schema = @Schema(
                                        implementation = AuthRequest.class
                                ))
                        )
                )
        )
    })
    public RouterFunction route() {
        return RouterFunctions.route()
                .GET("/auth/index", authHandler::index)
                .POST("/auth/login", authHandler::login)
                .POST("/auth/signup", authHandler::signUp)
                .build();
    }

}
