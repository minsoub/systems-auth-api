package com.bithumbsystems.auth.data.redis.repository;

import com.bithumbsystems.auth.data.redis.entity.OtpHistory;
import org.springframework.data.repository.CrudRepository;
import org.springframework.stereotype.Repository;

@Repository
public interface OtpHistoryCacheRepository extends CrudRepository<OtpHistory, String> {
}
