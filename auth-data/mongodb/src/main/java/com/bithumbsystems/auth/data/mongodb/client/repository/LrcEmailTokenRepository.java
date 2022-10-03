package com.bithumbsystems.auth.data.mongodb.client.repository;

import com.bithumbsystems.auth.data.mongodb.client.entity.LrcEmailToken;
import org.springframework.data.mongodb.repository.ReactiveMongoRepository;
import org.springframework.stereotype.Repository;

@Repository
public interface LrcEmailTokenRepository extends ReactiveMongoRepository<LrcEmailToken, String>  {
}
