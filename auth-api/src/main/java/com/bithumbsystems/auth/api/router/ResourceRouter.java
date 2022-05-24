//package com.bithumbsystems.auth.api.router;
//
//import com.bithumbsystems.auth.api.handler.ResourceHandler;
//import com.bithumbsystems.auth.core.model.request.token.AuthRequest;
//import com.bithumbsystems.auth.core.model.response.token.TokenResponse;
//import io.swagger.v3.oas.annotations.Operation;
//import io.swagger.v3.oas.annotations.media.Content;
//import io.swagger.v3.oas.annotations.media.Schema;
//import io.swagger.v3.oas.annotations.parameters.RequestBody;
//import io.swagger.v3.oas.annotations.responses.ApiResponse;
//import lombok.RequiredArgsConstructor;
//import org.springdoc.core.annotations.RouterOperation;
//import org.springdoc.core.annotations.RouterOperations;
//import org.springframework.context.annotation.Bean;
//import org.springframework.context.annotation.Configuration;
//import org.springframework.http.MediaType;
//import org.springframework.web.bind.annotation.RequestMethod;
//import org.springframework.web.reactive.function.server.RouterFunction;
//import org.springframework.web.reactive.function.server.RouterFunctions;
//
//@Configuration
//@RequiredArgsConstructor
//public class ResourceRouter {
//
//    private final ResourceHandler resourceHandler;
//
//    @Bean
//    @RouterOperations({
//        @RouterOperation(
//            path = "/api/v1/resources",
//            produces = {
//                MediaType.APPLICATION_JSON_VALUE
//            },
//            method = RequestMethod.GET,
//            beanClass = ResourceHandler.class,
//            beanMethod = "authorizationResources",
//            operation = @Operation(
//                operationId = "authorizationResources",
//                responses = {
//                    @ApiResponse(
//                            responseCode = "200",
//                            description = "successful operation",
//                            content = @Content(schema = @Schema(
//                                    implementation = TokenResponse.class
//                            ))
//                    )
//                },
//                requestBody = @RequestBody(
//                    content = @Content(schema = @Schema(
//                            implementation = AuthRequest.class
//                    ))
//                )
//            )
//        ),
//        @RouterOperation(
//            path = "/api/v1/resource",
//            produces = {
//                MediaType.APPLICATION_JSON_VALUE
//            },
//            method = RequestMethod.GET,
//            beanClass = ResourceHandler.class,
//            beanMethod = "authorizationResource",
//            operation = @Operation(
//                operationId = "authorizationResource",
//                responses = {
//                    @ApiResponse(
//                        responseCode = "200",
//                        description = "successful operation",
//                        content = @Content(schema = @Schema(
//                            implementation = TokenResponse.class
//                        ))
//                    )
//                },
//                requestBody = @RequestBody(
//                    content = @Content(schema = @Schema(
//                        implementation = AuthRequest.class
//                    ))
//                )
//            )
//        )
//    })
//    public RouterFunction route() {
//        return RouterFunctions.route()
//            .GET("/resource", resourceHandler::authorizationResource)
//            .GET("/resources", resourceHandler::authorizationResources)
//            .build();
//    }
//
//}
