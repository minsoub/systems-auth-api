package com.bithumbsystems.auth.data.mongodb.client.repository;

import com.bithumbsystems.auth.data.mongodb.client.entity.UserAccount;
import org.springframework.data.mongodb.repository.ReactiveMongoRepository;
import org.springframework.stereotype.Repository;
import reactor.core.publisher.Mono;

@Repository
public interface UserAccountRepository extends ReactiveMongoRepository<UserAccount, String> {
    Mono<UserAccount> findByEmail(String email);
}
