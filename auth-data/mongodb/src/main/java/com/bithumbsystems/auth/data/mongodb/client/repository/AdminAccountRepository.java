package com.bithumbsystems.auth.data.mongodb.client.repository;

import com.bithumbsystems.auth.data.mongodb.client.entity.AdminAccount;
import org.springframework.data.mongodb.repository.ReactiveMongoRepository;
import org.springframework.stereotype.Repository;
import reactor.core.publisher.Mono;

@Repository
public interface AdminAccountRepository extends ReactiveMongoRepository<AdminAccount, String> {
    Mono<AdminAccount> findByEmail(String email);

    Mono<AdminAccount> findByEmailAndPassword(String email, String password);
}
