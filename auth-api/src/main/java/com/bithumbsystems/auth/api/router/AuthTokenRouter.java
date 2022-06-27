package com.bithumbsystems.auth.api.router;

import com.bithumbsystems.auth.api.handler.AuthHandler;
import com.bithumbsystems.auth.core.model.auth.TokenInfo;
import com.bithumbsystems.auth.core.model.auth.TokenOtpInfo;
import com.bithumbsystems.auth.core.model.request.*;
import com.bithumbsystems.auth.core.model.request.token.AuthRequest;
import com.bithumbsystems.auth.core.model.response.ClientRegisterResponse;
import com.bithumbsystems.auth.core.model.response.OtpResponse;
import com.bithumbsystems.auth.core.model.response.SingleResponse;
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
        ),
        @RouterOperation(
                    path = "/api/v1/adm/login",
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
                                                    implementation = TokenOtpInfo.class
                                            ))
                                    )
                            },
                            requestBody = @RequestBody(
                                    content = @Content(schema = @Schema(
                                            implementation = UserRequest.class
                                    ))
                            )
                    )
        ),
        @RouterOperation(
                    path = "/api/v1/adm/otp",
                    produces = {
                            MediaType.APPLICATION_JSON_VALUE
                    },
                    method = RequestMethod.POST,
                    beanClass = AuthHandler.class,
                    beanMethod = "otp",
                    operation = @Operation(
                            operationId = "otp",
                            responses = {
                                    @ApiResponse(
                                            responseCode = "200",
                                            description = "successful operation",
                                            content = @Content(schema = @Schema(
                                                    implementation = TokenInfo.class
                                            ))
                                    )
                            },
                            requestBody = @RequestBody(
                                    content = @Content(schema = @Schema(
                                            implementation = OtpRequest.class
                                    ))
                            )
                    )
        ),
            @RouterOperation(
                    path = "/api/v1/adm/otp/clear",
                    produces = {
                            MediaType.APPLICATION_JSON_VALUE
                    },
                    method = RequestMethod.POST,
                    beanClass = AuthHandler.class,
                    beanMethod = "otpClear",
                    operation = @Operation(
                            operationId = "otpClear",
                            responses = {
                                    @ApiResponse(
                                            responseCode = "200",
                                            description = "successful operation",
                                            content = @Content(schema = @Schema(
                                                    implementation = TokenInfo.class
                                            ))
                                    )
                            },
                            requestBody = @RequestBody(
                                    content = @Content(schema = @Schema(
                                            implementation = OtpClearRequest.class
                                    ))
                            )
                    )
            ),
            @RouterOperation(
                    path = "/api/v1/user/login",
                    produces = {
                            MediaType.APPLICATION_JSON_VALUE
                    },
                    method = RequestMethod.POST,
                    beanClass = AuthHandler.class,
                    beanMethod = "userLogin",
                    operation = @Operation(
                            operationId = "userLogin",
                            responses = {
                                    @ApiResponse(
                                            responseCode = "200",
                                            description = "successful operation",
                                            content = @Content(schema = @Schema(
                                                    implementation = TokenOtpInfo.class
                                            ))
                                    )
                            },
                            requestBody = @RequestBody(
                                    content = @Content(schema = @Schema(
                                            implementation = UserRequest.class
                                    ))
                            )
                    )
            ),
            @RouterOperation(
                    path = "/api/v1/user/otp",
                    produces = {
                            MediaType.APPLICATION_JSON_VALUE
                    },
                    method = RequestMethod.POST,
                    beanClass = AuthHandler.class,
                    beanMethod = "userOtp",
                    operation = @Operation(
                            operationId = "userOtp",
                            responses = {
                                    @ApiResponse(
                                            responseCode = "200",
                                            description = "successful operation",
                                            content = @Content(schema = @Schema(
                                                    implementation = OtpResponse.class
                                            ))
                                    )
                            },
                            requestBody = @RequestBody(
                                    content = @Content(schema = @Schema(
                                            implementation = OtpRequest.class
                                    ))
                            )
                    )
            ),
            @RouterOperation(
                    path = "/api/v1/user/join",
                    produces = {
                            MediaType.APPLICATION_JSON_VALUE
                    },
                    method = RequestMethod.POST,
                    beanClass = AuthHandler.class,
                    beanMethod = "userJoin",
                    operation = @Operation(
                            operationId = "userJoin",
                            responses = {
                                    @ApiResponse(
                                            responseCode = "200",
                                            description = "successful operation",
                                            content = @Content(schema = @Schema(
                                                    implementation = SingleResponse.class
                                            ))
                                    )
                            },
                            requestBody = @RequestBody(
                                    content = @Content(schema = @Schema(
                                            implementation = UserJoinRequest.class
                                    ))
                            )
                    )
            ),
            @RouterOperation(
                    path = "/api/v1/authorize",
                    produces = {
                            MediaType.APPLICATION_JSON_VALUE
                    },
                    method = RequestMethod.POST,
                    beanClass = AuthHandler.class,
                    beanMethod = "tokenValidate",
                    operation = @Operation(
                            operationId = "tokenValidate",
                            responses = {
                                    @ApiResponse(
                                            responseCode = "200",
                                            description = "successful operation",
                                            content = @Content(schema = @Schema(
                                                    implementation = String.class
                                            ))
                                    )
                            },
                            requestBody = @RequestBody(
                                    content = @Content(schema = @Schema(
                                            implementation = TokenValidationRequest.class
                                    ))
                            )
                    )
            ),
    })
    public RouterFunction route() {
        return RouterFunctions.route()
            .POST("/api/v1/client", authHandler::registerClient)
            .POST("/api/v1/token", authHandler::generateToken)
            .PUT("/api/v1/token", authHandler::refreshToken)
            .DELETE("/api/v1/token", authHandler::deleteToken)
            .POST("/api/v1/adm/login", authHandler::login)
            .POST("/api/v1/adm/otp", authHandler::otp)
            .POST("/api/v1/adm/otp/clear", authHandler::otpClear)
            .POST("/api/v1/user/login", authHandler::userLogin)
            .POST("/api/v1/user/captcha-login", authHandler::userCaptchaLogin)
            .POST("/api/v1/user/otp", authHandler::userOtp)
            .POST("/api/v1/user/join", authHandler::userJoin)
            .POST("/api/v1/authorize", authHandler::tokenValidate)
            .build();
    }

}
