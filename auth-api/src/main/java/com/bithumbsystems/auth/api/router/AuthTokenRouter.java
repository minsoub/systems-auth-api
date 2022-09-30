package com.bithumbsystems.auth.api.router;

import com.bithumbsystems.auth.api.handler.AdminAuthHandler;
import com.bithumbsystems.auth.api.handler.AuthHandler;
import com.bithumbsystems.auth.api.handler.UserAuthHandler;
import com.bithumbsystems.auth.core.model.auth.TokenInfo;
import com.bithumbsystems.auth.core.model.auth.TokenOtpInfo;
import com.bithumbsystems.auth.core.model.request.OtpClearRequest;
import com.bithumbsystems.auth.core.model.request.OtpRequest;
import com.bithumbsystems.auth.core.model.request.TokenValidationRequest;
import com.bithumbsystems.auth.core.model.request.UserJoinRequest;
import com.bithumbsystems.auth.core.model.request.UserRequest;
import com.bithumbsystems.auth.core.model.request.token.AuthRequest;
import com.bithumbsystems.auth.core.model.response.KeyResponse;
import com.bithumbsystems.auth.core.model.response.PublicKeyResponse;
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

  private final AdminAuthHandler adminAuthHandler;
  private final UserAuthHandler userAuthHandler;
  private final AuthHandler authHandler;

    @Bean
    @RouterOperations({
            @RouterOperation(
                    path = "/api/v1/adm/init",
                    produces = {
                            MediaType.APPLICATION_JSON_VALUE
                    },
                    method = RequestMethod.GET,
                    beanClass = AdminAuthHandler.class,
                    beanMethod = "initKey",
                    operation = @Operation(
                            operationId = "initKey",
                            responses = {
                                    @ApiResponse(
                                            responseCode = "200",
                                            description = "successful operation",
                                            content = @Content(schema = @Schema(
                                                    implementation = KeyResponse.class
                                            ))
                                    )
                            }
                    )
            ),
        @RouterOperation(
            path = "/api/v1/adm/token",
            produces = {
                MediaType.APPLICATION_JSON_VALUE
            },
            method = RequestMethod.PUT,
            beanClass = AdminAuthHandler.class,
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
                    path = "/api/v1/adm/login",
                    produces = {
                            MediaType.APPLICATION_JSON_VALUE
                    },
                    method = RequestMethod.POST,
                    beanClass = AdminAuthHandler.class,
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
                    path = "/api/v1/adm/temp-password-init",
                    produces = {
                            MediaType.APPLICATION_JSON_VALUE
                    },
                    method = RequestMethod.POST,
                    beanClass = AdminAuthHandler.class,
                    beanMethod = "sendTempPasswordInit",
                    operation = @Operation(
                            operationId = "sendTempPasswordInit",
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
                                            implementation = String.class
                                    ))
                            )
                    )
            ),
        @RouterOperation(
            path = "/api/v1/adm/temp-password",
            produces = {
                MediaType.APPLICATION_JSON_VALUE
            },
            method = RequestMethod.POST,
            beanClass = AdminAuthHandler.class,
            beanMethod = "sendTempPasswordMail",
            operation = @Operation(
                operationId = "sendTempPasswordMail",
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
                        implementation = String.class
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
                    beanClass = AdminAuthHandler.class,
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
                    path = "/api/v1/adm/password",
                    produces = {
                            MediaType.APPLICATION_JSON_VALUE
                    },
                    method = RequestMethod.POST,
                    beanClass = AdminAuthHandler.class,
                    beanMethod = "passwordUpdate",
                    operation = @Operation(
                            operationId = "passwordUpdate",
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
                                            implementation = UserRequest.class
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
                    beanClass = AdminAuthHandler.class,
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
                path = "/api/v1/adm/public-key",
                produces = {
                    MediaType.APPLICATION_JSON_VALUE
                },
                method = RequestMethod.GET,
                beanClass = AuthHandler.class,
                beanMethod = "publicKey",
                operation = @Operation(
                    operationId = "publicKey",
                    responses = {
                        @ApiResponse(
                            responseCode = "200",
                            description = "successful operation",
                            content = @Content(schema = @Schema(
                                implementation = PublicKeyResponse.class
                            ))
                        )
                    }
                )
            ),
            @RouterOperation(
                    path = "/api/v1/user/init",
                    produces = {
                            MediaType.APPLICATION_JSON_VALUE
                    },
                    method = RequestMethod.GET,
                    beanClass = AdminAuthHandler.class,
                    beanMethod = "initKey",
                    operation = @Operation(
                            operationId = "initKey",
                            responses = {
                                    @ApiResponse(
                                            responseCode = "200",
                                            description = "successful operation",
                                            content = @Content(schema = @Schema(
                                                    implementation = KeyResponse.class
                                            ))
                                    )
                            }
                    )
            ),
            @RouterOperation(
                    path = "/api/v1/user/login",
                    produces = {
                            MediaType.APPLICATION_JSON_VALUE
                    },
                    method = RequestMethod.POST,
                    beanClass = UserAuthHandler.class,
                    beanMethod = "",
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
                    path = "/api/v1/user/join",
                    produces = {
                            MediaType.APPLICATION_JSON_VALUE
                    },
                    method = RequestMethod.POST,
                    beanClass = UserAuthHandler.class,
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
                path = "/api/v1/user/public-key",
                produces = {
                    MediaType.APPLICATION_JSON_VALUE
                },
                method = RequestMethod.GET,
                beanClass = AuthHandler.class,
                beanMethod = "publicKey",
                operation = @Operation(
                    operationId = "publicKey",
                    responses = {
                        @ApiResponse(
                            responseCode = "200",
                            description = "successful operation",
                            content = @Content(schema = @Schema(
                                implementation = PublicKeyResponse.class
                            ))
                        )
                    }
                )
            ),
            @RouterOperation(
                    path = "/api/v1/authorize",
                    produces = {
                            MediaType.APPLICATION_JSON_VALUE
                    },
                    method = RequestMethod.POST,
                    beanClass = UserAuthHandler.class,
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
            .GET("/api/v1/adm/init", adminAuthHandler::initKey)
            .PUT("/api/v1/adm/token", adminAuthHandler::refreshToken)
            .POST("/api/v1/adm/login", adminAuthHandler::login)
            .POST("/api/v1/adm/temp-password-init", adminAuthHandler::sendTempPasswordInit)
            .POST("/api/v1/adm/temp-password", adminAuthHandler::sendTempPasswordMail)
            .POST("/api/v1/adm/otp", adminAuthHandler::otp)
            .POST("/api/v1/adm/password", adminAuthHandler::passwordUpdate)
            .POST("/api/v1/adm/otp/clear", adminAuthHandler::otpClear)
            .GET("/api/v1/adm/public-key", authHandler::publicKey)
            .GET("/api/v1/user/init", userAuthHandler::initKey)
            .PUT("/api/v1/user/token", userAuthHandler::refreshToken)
            .POST("/api/v1/user/login", userAuthHandler::userLogin)
            .POST("/api/v1/user/captcha-login", userAuthHandler::userCaptchaLogin)
            .POST("/api/v1/user/join", userAuthHandler::userJoin)
            .GET("/api/v1/user/public-key", authHandler::publicKey)
            .POST("/api/v1/authorize", authHandler::authorize)
            .POST("/api/v1/user/otp", userAuthHandler::otp)
            .build();
    }

}
