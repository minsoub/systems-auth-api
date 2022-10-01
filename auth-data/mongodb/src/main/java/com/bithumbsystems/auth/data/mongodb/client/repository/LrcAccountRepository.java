package com.bithumbsystems.auth.data.mongodb.client.repository;

import com.bithumbsystems.auth.data.mongodb.client.entity.LrcAccount;
import org.springframework.data.mongodb.repository.ReactiveMongoRepository;
import org.springframework.stereotype.Repository;
import reactor.core.publisher.Mono;

@Repository
public interface LrcAccountRepository extends ReactiveMongoRepository<LrcAccount, String> {
    Mono<LrcAccount> findByEmail(String email);
}
