package com.bithumbsystems.auth.data.mongodb.client.service;

import com.bithumbsystems.auth.data.mongodb.client.entity.AdminAccess;
import com.bithumbsystems.auth.data.mongodb.client.repository.AdminAccessRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Service;
import reactor.core.publisher.Mono;

@Service
@RequiredArgsConstructor
public class AdminAccessDomainService {
    private final AdminAccessRepository repository;


    public Mono<AdminAccess> findByAdminId(String admin_id) {
        return repository.findByAdmin_account_id(admin_id);
    }
}
