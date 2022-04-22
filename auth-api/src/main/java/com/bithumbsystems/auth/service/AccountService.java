package com.bithumbsystems.auth.service;

import com.bithumbsystems.auth.api.exception.NotExistAccountException;
import com.bithumbsystems.auth.api.exception.security.AuthException;
import com.bithumbsystems.auth.core.model.auth.TokenInfo;
import com.bithumbsystems.auth.core.model.enums.TokenType;
import com.bithumbsystems.auth.core.model.mapper.AccountMapper;
import com.bithumbsystems.auth.core.model.request.AuthRequest;
import com.bithumbsystems.auth.core.model.request.SignUpRequest;
import com.bithumbsystems.auth.core.model.response.SignUpResponse;
import com.bithumbsystems.auth.data.mongodb.entity.Account;
import com.bithumbsystems.auth.data.mongodb.service.AccountDomainService;
import com.bithumbsystems.auth.service.security.JwtGenerateService;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import reactor.core.publisher.Mono;

@Service
@Slf4j
@RequiredArgsConstructor
public class AccountService {

    private final AccountDomainService accountDomainService;
    private final PasswordEncoder passwordEncoder;
    private final JwtGenerateService jwtGenerateService;
    private final AccountMapper accountMapper;

    public Mono<TokenInfo> login(Mono<AuthRequest> authRequest) {
        return authRequest.flatMap(request -> authenticate(request.getEmail(), request.getPassword()));
    }

    public Mono<Account> findByEmail(String email) {
        return accountDomainService.findByEmail(email)
                .switchIfEmpty(Mono.error( new NotExistAccountException("not exist")));
    }

    public Mono<SignUpResponse> signUp(Mono<SignUpRequest> signUpRequest) {
        return signUpRequest.map(
                request -> {
                    request.setPassword(passwordEncoder.encode(request.getPassword()));
                    return accountMapper.requestToEntity(request);
                }
        ).map(accountMapper::entityToResponse).doOnSuccess(u -> log.info("Created new user with ID = " + u.getEmail()));

    }

    public Mono<TokenInfo> authenticate(String email, String password) {
        return findByEmail(email)
                .flatMap(account -> {
                    if (!account.isEnabled())
                        return Mono.error(new AuthException("Account disabled.", "USER_ACCOUNT_DISABLED"));

                    if (!passwordEncoder.encode(password).equals(account.getPassword()))
                        return Mono.error(new AuthException("Invalid user password!", "INVALID_USER_PASSWORD"));

                    return Mono.just(jwtGenerateService.generateAccessToken(account, TokenType.ACCESS).toBuilder()
                            .email(account.getEmail())
                            .build());
                })
                .switchIfEmpty(Mono.error(new AuthException("Invalid user, " + email + " is not registered.", "INVALID_USERNAME")));
    }
}
