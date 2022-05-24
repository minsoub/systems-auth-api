package com.bithumbsystems.auth.api.handler;

import com.bithumbsystems.auth.core.model.auth.TokenInfo;
import com.bithumbsystems.auth.core.model.request.ClientRegisterRequest;
import com.bithumbsystems.auth.core.model.request.token.AuthRequest;
import com.bithumbsystems.auth.core.model.response.token.TokenResponse;
import com.bithumbsystems.auth.service.AuthService;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Component;
import org.springframework.web.reactive.function.server.ServerRequest;
import org.springframework.web.reactive.function.server.ServerResponse;
import reactor.core.publisher.Mono;

@Component
@RequiredArgsConstructor
public class AuthHandler {

    private final AuthService authService;

    public Mono<ServerResponse> registerClient(ServerRequest request) {
        Mono<ClientRegisterRequest> clientRegisterRequestMono = request.bodyToMono(ClientRegisterRequest.class);
        return ServerResponse.ok().body(authService.registerClient(clientRegisterRequestMono), TokenResponse.class);
    }

    public Mono<ServerResponse> generateToken(ServerRequest request) {
        Mono<AuthRequest> authRequest = request.bodyToMono(AuthRequest.class);
        return ServerResponse.ok().body(authService.generateToken(authRequest), TokenResponse.class);
    }

    public Mono<ServerResponse> refreshToken(ServerRequest request) {
        Mono<AuthRequest> authRequest = request.bodyToMono(AuthRequest.class);
        return ServerResponse.ok().body(null, TokenInfo.class);
    }

    public Mono<ServerResponse> deleteToken(ServerRequest request) {
        Mono<AuthRequest> authRequest = request.bodyToMono(AuthRequest.class);
        return ServerResponse.ok().body(null, TokenInfo.class);
    }

}
