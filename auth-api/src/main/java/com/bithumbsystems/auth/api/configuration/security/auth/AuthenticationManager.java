package com.bithumbsystems.auth.api.configuration.security.auth;

import com.bithumbsystems.auth.api.exception.security.UnauthorizedException;
import com.bithumbsystems.auth.core.model.auth.UserPrincipal;
import com.bithumbsystems.auth.data.mongodb.entity.Account;
import com.bithumbsystems.auth.service.AccountService;
import lombok.RequiredArgsConstructor;
import org.springframework.security.authentication.ReactiveAuthenticationManager;
import org.springframework.security.core.Authentication;
import org.springframework.stereotype.Component;
import reactor.core.publisher.Mono;

@Component
@RequiredArgsConstructor
public class AuthenticationManager implements ReactiveAuthenticationManager {

    private final AccountService accountService;

    @Override
    public Mono<Authentication> authenticate(Authentication authentication) {

        var principal = (UserPrincipal) authentication.getPrincipal();

        return accountService.findByEmail(principal.getId())
                .filter(Account::isEnabled)
                .switchIfEmpty(Mono.error(new UnauthorizedException("Account is disabled.")))
                .map(user -> authentication);
    }
}