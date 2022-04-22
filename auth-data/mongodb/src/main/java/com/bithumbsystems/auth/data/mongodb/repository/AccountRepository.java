package com.bithumbsystems.auth.data.mongodb.repository;

import com.bithumbsystems.auth.data.mongodb.entity.Account;
import org.springframework.data.mongodb.repository.ReactiveMongoRepository;
import org.springframework.stereotype.Repository;
import reactor.core.publisher.Mono;

@Repository
public interface AccountRepository extends ReactiveMongoRepository<Account, String> {
    Mono<Account> findByEmail(String email);
}
