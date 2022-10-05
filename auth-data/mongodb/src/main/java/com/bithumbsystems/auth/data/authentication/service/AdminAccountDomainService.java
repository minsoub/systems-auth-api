package com.bithumbsystems.auth.data.authentication.service;

import com.bithumbsystems.auth.data.authentication.entity.AdminAccount;
import com.bithumbsystems.auth.data.authentication.repository.AdminAccountRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Service;
import reactor.core.publisher.Mono;

/**
 * The type Admin account domain service.
 */
@Service
@RequiredArgsConstructor
public class AdminAccountDomainService {
    private final AdminAccountRepository repository;

    /**
     * 사용자 정보 조회
     *
     * @param id the id
     * @return mono
     */
    public Mono<AdminAccount> findById(String id) {
        return repository.findById(id);
    }

    /**
     * 사용자 이메일을 통해서 사용자 정보를 조회한다. 사용자 이메일을 통해서 사용자 정보를 조회한다.
     *
     * @param email the email
     * @return mono
     */
    public Mono<AdminAccount> findByEmail(String email) {
        return repository.findByEmail(email);
    }

    /**
     * 아이디와 패스워드를 통해서 사용자 정보를 조회한다.
     *
     * @param email    the email
     * @param password the password
     * @return mono
     */
    public Mono<AdminAccount> findByEmailAndPassword(String email, String password) {
        return repository.findByEmailAndPassword(email, password);
    }

    /**
     * 사용자 계정정보를 저장한다.
     *
     * @param data the data
     * @return mono
     */
    public Mono<AdminAccount> save(AdminAccount data) {
        return repository.save(data);
    }
}
