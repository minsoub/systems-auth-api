package com.bithumbsystems.auth.api.router;

import com.bithumbsystems.auth.api.handler.AuthHandler;
import com.bithumbsystems.auth.core.model.request.token.AuthRequest;
import com.bithumbsystems.auth.core.model.response.ClientRegisterResponse;
import com.bithumbsystems.auth.core.model.response.token.TokenResponse;
import io.swagger.v3.oas.annotations.Operation;
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
public class AuthTokenRouter {

    private final AuthHandler authHandler;

    @Bean
    @RouterOperations({
        @RouterOperation(
            path = "/api/v1/client",
            produces = {
                MediaType.APPLICATION_JSON_VALUE
            },
            method = RequestMethod.POST,
            beanClass = AuthHandler.class,
            beanMethod = "registerClient",
            operation = @Operation(
                operationId = "registerClient",
                responses = {
                    @ApiResponse(
                        responseCode = "200",
                        description = "successful operation",
                        content = @Content(schema = @Schema(
                            implementation = ClientRegisterResponse.class
                        ))
                    )
                },
                requestBody = @RequestBody(
                    content = @Content(schema = @Schema(
                        implementation = ClientRegisterResponse.class
                    ))
                )
            )
        ),
            @RouterOperation(
            path = "/api/v1/token",
            produces = {
                MediaType.APPLICATION_JSON_VALUE
            },
            method = RequestMethod.POST,
            beanClass = AuthHandler.class,
            beanMethod = "generateToken",
            operation = @Operation(
                operationId = "generateToken",
                responses = {
                    @ApiResponse(
                        responseCode = "200",
                        description = "successful operation",
                        content = @Content(schema = @Schema(
                            implementation = TokenResponse.class
                        ))
                    )
                },
                requestBody = @RequestBody(
                    content = @Content(schema = @Schema(
                        implementation = AuthRequest.class
                    ))
                )
            )
        ),
        @RouterOperation(
            path = "/api/v1/token",
            produces = {
                MediaType.APPLICATION_JSON_VALUE
            },
            method = RequestMethod.GET,
            beanClass = AuthHandler.class,
            beanMethod = "refreshToken",
            operation = @Operation(
                operationId = "refreshToken",
                responses = {
                    @ApiResponse(
                        responseCode = "200",
                        description = "successful operation",
                        content = @Content(schema = @Schema(
                            implementation = TokenResponse.class
                        ))
                    )
                },
                requestBody = @RequestBody(
                    content = @Content(schema = @Schema(
                        implementation = AuthRequest.class
                    ))
                )
            )
        ),
        @RouterOperation(
            path = "/api/v1/token",
            produces = {
                MediaType.APPLICATION_JSON_VALUE
            },
            method = RequestMethod.DELETE,
            beanClass = AuthHandler.class,
            beanMethod = "deleteToken",
            operation = @Operation(
                operationId = "deleteToken",
                responses = {
                    @ApiResponse(
                        responseCode = "200",
                        description = "successful operation",
                        content = @Content(schema = @Schema(
                            implementation = TokenResponse.class
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
            .POST("/api/v1/client", authHandler::registerClient)
            .POST("/api/v1/token", authHandler::generateToken)
            .PUT("/api/v1/token", authHandler::refreshToken)
            .DELETE("/api/v1/token", authHandler::deleteToken)
            .POST("/api/v1/adm/login", authHandler::login)
            .POST("/api/v1/adm/otp", authHandler::otp)
            .POST("/api/v1/user/login", authHandler::userLogin)
            .build();
    }

}
