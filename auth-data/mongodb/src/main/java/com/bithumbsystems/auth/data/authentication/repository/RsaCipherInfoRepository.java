package com.bithumbsystems.auth.data.authentication.repository;

import com.bithumbsystems.auth.data.authentication.entity.RsaCipherInfo;
import org.springframework.data.mongodb.repository.ReactiveMongoRepository;
import org.springframework.stereotype.Repository;

@Repository
public interface RsaCipherInfoRepository extends ReactiveMongoRepository<RsaCipherInfo, String> {
}
