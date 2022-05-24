package com.bithumbsystems.auth.service;

import com.bithumbsystems.auth.data.mongodb.client.entity.AdminAccess;
import com.bithumbsystems.auth.data.mongodb.client.service.AdminAccessDomainService;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Service;
import reactor.core.publisher.Mono;

@Service
@Slf4j
@RequiredArgsConstructor
public class AdminAccessService {
    private final AdminAccessDomainService service;

    public Mono<AdminAccess> findByAdminId(String admin_account_id) {
        return service.findByAdminId(admin_account_id);
    }
}
