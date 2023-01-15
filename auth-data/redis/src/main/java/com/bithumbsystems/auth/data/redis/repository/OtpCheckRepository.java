package com.bithumbsystems.auth.data.redis.repository;

import com.bithumbsystems.auth.data.redis.entity.OtpCheck;
import org.springframework.data.repository.reactive.ReactiveCrudRepository;
import org.springframework.stereotype.Repository;

@Repository
public interface OtpCheckRepository extends ReactiveCrudRepository<OtpCheck, String> {
}