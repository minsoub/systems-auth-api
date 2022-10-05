package com.bithumbsystems.auth.data.authorization.service;

import com.bithumbsystems.auth.data.authorization.entity.Program;
import com.bithumbsystems.auth.data.authorization.repository.ProgramRepository;
import com.bithumbsystems.auth.data.authorization.repository.RoleAuthorizationRepository;
import java.util.stream.Collectors;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Service;
import reactor.core.publisher.Flux;
import reactor.core.publisher.Mono;

@Service
@Slf4j
@RequiredArgsConstructor
public class AuthorizationService {

  private final RoleAuthorizationRepository roleAuthorizationRepository;

  private final ProgramRepository programRepository;

  public Flux<Program> findRolePrograms(String roleManagementId) {
    return roleAuthorizationRepository.findByRoleManagementId(roleManagementId)
        .flatMap(roleAuthorization -> Mono.just(roleAuthorization
          .getAuthorizationResources()
          .stream()
          .flatMap(authorizationResource -> authorizationResource.getProgramId().stream()).collect(Collectors.toList())))
        .flatMap(programRepository::findByIdIn);
  }
}
