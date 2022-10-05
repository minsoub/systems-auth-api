package com.bithumbsystems.auth.data.authentication.service;

import com.bithumbsystems.auth.data.authentication.entity.UserAccount;
import com.bithumbsystems.auth.data.authentication.repository.UserAccountRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Service;
import reactor.core.publisher.Mono;

@Service
@RequiredArgsConstructor
public class UserAccountDomainService {
    private final UserAccountRepository repository;

    /**
     * 사용자 이메일 정보를 통해서 사용자 정보를 조회한다.
     *
     * @param email
     * @return
     */
    public Mono<UserAccount> findByEmail(String email) {
        return repository.findByEmail(email);
    }

    /**
     * 사용자 정보를 저장한다.
     *
     * @param user
     * @return
     */
    public Mono<UserAccount> save(UserAccount user) {
        return repository.save(user);
    }

    /**
     * 사용자 키를 통해서 사용자 정보를 리턴한다.
     * @param id
     * @return
     */
    public Mono<UserAccount> findById(String id) {
        return repository.findById(id);
    }

}
