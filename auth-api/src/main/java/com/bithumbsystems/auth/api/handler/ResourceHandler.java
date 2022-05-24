package com.bithumbsystems.auth.api.handler;

import com.bithumbsystems.auth.core.model.auth.TokenInfo;
import com.bithumbsystems.auth.core.model.request.token.AuthRequest;
import com.bithumbsystems.auth.service.ResourceService;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Component;
import org.springframework.web.reactive.function.server.ServerRequest;
import org.springframework.web.reactive.function.server.ServerResponse;
import reactor.core.publisher.Mono;

@Component
@RequiredArgsConstructor
public class ResourceHandler {

    private final ResourceService resourceService;

    public Mono<ServerResponse> authorizationResources(ServerRequest request) {
        Mono<AuthRequest> authRequest = request.bodyToMono(AuthRequest.class);
        return ServerResponse.ok().body(null, TokenInfo.class);
    }

    public Mono<ServerResponse> authorizationResource(ServerRequest request) {
        Mono<AuthRequest> authRequest = request.bodyToMono(AuthRequest.class);
        return ServerResponse.ok().body(null, TokenInfo.class);
    }
}
