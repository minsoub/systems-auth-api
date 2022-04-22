package com.bithumbsystems.auth.data.mongodb.service;

import com.bithumbsystems.auth.data.mongodb.entity.Account;
import com.bithumbsystems.auth.data.mongodb.repository.AccountRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Service;
import reactor.core.publisher.Mono;

@Service
@RequiredArgsConstructor
public class AccountDomainService {

    private final AccountRepository accountRepository;

    public Mono<Account> findByEmail(String email) {
        return accountRepository.findByEmail(email);
    }

    public Mono<Account> findById(String id) {
        return accountRepository.findById(id);
    }

    public Mono<Account> save(Account account) {
        return accountRepository.save(account);
    }
}

