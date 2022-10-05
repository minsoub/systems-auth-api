package com.bithumbsystems.auth.data.authorization.repository;

import com.bithumbsystems.auth.data.authorization.entity.RoleAuthorization;
import org.springframework.data.mongodb.repository.ReactiveMongoRepository;
import reactor.core.publisher.Flux;

public interface RoleAuthorizationRepository extends ReactiveMongoRepository<RoleAuthorization, String> {

  Flux<RoleAuthorization> findByRoleManagementId(String roleManagementId);

}