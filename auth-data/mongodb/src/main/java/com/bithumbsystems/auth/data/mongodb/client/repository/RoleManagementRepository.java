package com.bithumbsystems.auth.data.mongodb.client.repository;


import com.bithumbsystems.auth.data.mongodb.client.entity.RoleManagement;
import java.time.LocalDate;
import java.time.LocalDateTime;
import java.util.Set;
import org.springframework.data.mongodb.repository.ReactiveMongoRepository;
import reactor.core.publisher.Flux;
import reactor.core.publisher.Mono;

public interface RoleManagementRepository extends ReactiveMongoRepository<RoleManagement, String> {

  Mono<RoleManagement> findFirstByIdInAndValidStartDateBeforeAndValidEndDateAfterAndIsUse(
      Set<String> roles,
      LocalDate now,
      LocalDate now2,
      Boolean isUse
  );

  Flux<RoleManagement> findByIdInAndValidStartDateBeforeAndValidEndDateAfterAndIsUseTrue(Set<String> roles, LocalDateTime now, LocalDateTime now2);

}
