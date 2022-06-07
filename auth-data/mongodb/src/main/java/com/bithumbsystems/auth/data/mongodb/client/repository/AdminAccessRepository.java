package com.bithumbsystems.auth.data.mongodb.client.repository;

import com.bithumbsystems.auth.data.mongodb.client.entity.AdminAccess;
import org.springframework.data.mongodb.repository.Query;
import org.springframework.data.mongodb.repository.ReactiveMongoRepository;
import org.springframework.stereotype.Repository;
import reactor.core.publisher.Mono;

@Repository
public interface AdminAccessRepository extends ReactiveMongoRepository<AdminAccess, String> {

     @Query("{ 'admin_account_id' : ?0 }")
     Mono<AdminAccess> findByAdminAccountId(String adminAccountId) ;

}
