package com.bithumbsystems.auth.service.authorization;

import com.bithumbsystems.auth.core.model.auth.UserPrincipal;
import com.bithumbsystems.auth.service.AuthService;
import lombok.RequiredArgsConstructor;
import org.springframework.security.authentication.ReactiveAuthenticationManager;
import org.springframework.security.core.Authentication;
import org.springframework.stereotype.Component;
import reactor.core.publisher.Mono;

@Component
@RequiredArgsConstructor
public class AuthenticationManager implements ReactiveAuthenticationManager {

    private final AuthService authService;

    @Override
    public Mono<Authentication> authenticate(Authentication authentication) {

        var principal = (UserPrincipal) authentication.getPrincipal();

//        return authService.findByEmail(principal.getEmail())
//                .filter(AdminAccount::isEnabled)
//                .switchIfEmpty(Mono.error(new UnauthorizedException(ErrorCode.USER_ACCOUNT_DISABLED)))
//                .map(user -> authentication);
        return Mono.just(authentication);
    }
}