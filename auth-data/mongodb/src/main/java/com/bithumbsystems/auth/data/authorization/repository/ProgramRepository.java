package com.bithumbsystems.auth.data.authorization.repository;

import com.bithumbsystems.auth.data.authorization.entity.Program;
import java.util.List;
import org.springframework.data.mongodb.repository.ReactiveMongoRepository;
import reactor.core.publisher.Flux;

public interface ProgramRepository extends ReactiveMongoRepository<Program, String> {

  Flux<Program> findByIdIn(List<String> ids);
}
