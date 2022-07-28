package com.bithumbsystems.auth.data.mongodb.client.service;


import com.bithumbsystems.auth.data.mongodb.client.entity.RoleManagement;
import com.bithumbsystems.auth.data.mongodb.client.repository.RoleManagementRepository;
import java.time.LocalDate;
import java.time.LocalDateTime;
import java.util.Set;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Service;
import reactor.core.publisher.Flux;
import reactor.core.publisher.Mono;

@Service
@RequiredArgsConstructor
public class RoleManagementDomainService {

  private final RoleManagementRepository roleManagementRepository;

  public Mono<RoleManagement> findFirstRole(Set<String> roles) {
    return roleManagementRepository.findFirstByIdInAndValidStartDateBeforeAndValidEndDateAfterAndIsUse(
        roles,
        LocalDate.now(),
        LocalDate.now(),
        true);
  }

  public Flux<RoleManagement> findByRoleInIds(Set<String> roleManagementIds) {
    return roleManagementRepository.findByIdInAndValidStartDateBeforeAndValidEndDateAfterAndIsUseTrue(roleManagementIds, LocalDateTime.now(), LocalDateTime.now());
  }

}
