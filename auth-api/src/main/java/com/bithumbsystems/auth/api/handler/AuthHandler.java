package com.bithumbsystems.auth.api.handler;

import com.bithumbsystems.auth.core.model.auth.TokenInfo;
import com.bithumbsystems.auth.core.model.request.AuthRequest;
import com.bithumbsystems.auth.core.model.request.SignUpRequest;
import com.bithumbsystems.auth.service.AccountService;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Component;
import org.springframework.web.reactive.function.BodyInserters;
import org.springframework.web.reactive.function.server.ServerRequest;
import org.springframework.web.reactive.function.server.ServerResponse;
import reactor.core.publisher.Mono;

@Component
@RequiredArgsConstructor
public class AuthHandler {

    private final AccountService accountService;

    public Mono<ServerResponse> login(ServerRequest request) {
        Mono authRequest = request.bodyToMono(AuthRequest.class);
        return ServerResponse.ok().body(accountService.login(authRequest), TokenInfo.class);
    }

    public Mono<ServerResponse> signUp(ServerRequest request) {
        Mono signUpRequest = request.bodyToMono(SignUpRequest.class);
        return ServerResponse.ok().body(BodyInserters.fromValue(accountService.signUp(signUpRequest)));
    }

    public Mono<ServerResponse> index(ServerRequest request) {
        return ServerResponse.ok().bodyValue("index");
    }
}
