package com.bithumbsystems.auth.service;

import static com.bithumbsystems.auth.core.model.enums.ErrorCode.INVALID_TOKEN;
import static com.bithumbsystems.auth.core.util.JwtGenerateUtil.generate;

import com.bithumbsystems.auth.api.config.property.JwtProperties;
import com.bithumbsystems.auth.api.exception.authorization.UnauthorizedException;
import com.bithumbsystems.auth.core.model.auth.GenerateTokenInfo;
import com.bithumbsystems.auth.core.model.auth.TokenInfo;
import com.bithumbsystems.auth.core.model.enums.TokenType;
import com.bithumbsystems.auth.core.model.mapper.ClientMapper;
import com.bithumbsystems.auth.core.model.request.ClientRegisterRequest;
import com.bithumbsystems.auth.core.model.request.TokenValidationRequest;
import com.bithumbsystems.auth.core.model.request.token.AuthRequest;
import com.bithumbsystems.auth.core.model.response.ClientRegisterResponse;
import com.bithumbsystems.auth.core.util.JwtVerifyUtil;
import com.bithumbsystems.auth.data.mongodb.client.service.ClientDomainService;
import com.bithumbsystems.auth.data.redis.RedisTemplateSample;
import java.util.Map;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Service;
import reactor.core.publisher.Mono;

@Service
@Slf4j
@RequiredArgsConstructor
public class AuthService {

    private final JwtProperties jwtProperties;

    private final ClientDomainService clientDomainService;

    private final RedisTemplateSample redisTemplateSample;

    public Mono<TokenInfo> generateToken(Mono<AuthRequest> authRequest) {
        return authRequest.flatMap(
            request -> {
                GenerateTokenInfo generateTokenInfo = GenerateTokenInfo
                    .builder()
                    .secret(jwtProperties.getSecret())
                    .expiration(jwtProperties.getExpiration().get(TokenType.ACCESS.getValue()))
                    .subject(request.getClientId())
                    .issuer(request.getEmail())
                    .claims(Map.of("ROLE", "TEST"))
                    .build();

                var tokenInfo = generate(generateTokenInfo)
                    .toBuilder()
                    .build();
                redisTemplateSample.saveToken(request.getEmail(), tokenInfo.toString());
              return Mono.just(tokenInfo);
            }
        );
    }

    public Mono<ClientRegisterResponse> registerClient(Mono<ClientRegisterRequest> clientRegisterRequestMono) {
        return clientRegisterRequestMono
            .flatMap(clientRegisterRequest -> clientDomainService.save(ClientMapper.INSTANCE.clientRegisterRequestToClient(clientRegisterRequest)))
            .flatMap(client -> Mono.just(ClientMapper.INSTANCE.clientToClientRegisterResponse(client)));
    }

    /**
     * Token Validation 을 체크한다.
     *
     * @param tokenValidationRequestMono
     * @return
     */
    public Mono<String> tokenValidate(Mono<TokenValidationRequest> tokenValidationRequestMono) {
        return tokenValidationRequestMono
                .flatMap(res -> JwtVerifyUtil.check(res.getToken(), jwtProperties.getSecret())
                        .map(result -> "Success"));
    }
}
