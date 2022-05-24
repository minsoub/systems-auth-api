package com.bithumbsystems.auth.data.mongodb.client.service;

import com.bithumbsystems.auth.data.mongodb.client.entity.UserAccount;
import com.bithumbsystems.auth.data.mongodb.client.repository.UserAccountRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Service;
import reactor.core.publisher.Mono;

@Service
@RequiredArgsConstructor
public class UserAccountDomainService {
    private final UserAccountRepository repository;

    public Mono<UserAccount> findByEmail(String email) {
        return repository.findByEmail(email);
    }
}
