package com.bithumbsystems.auth.data.mongodb.client.service;

import com.bithumbsystems.auth.data.mongodb.client.entity.LrcAccount;
import com.bithumbsystems.auth.data.mongodb.client.entity.LrcEmailToken;
import com.bithumbsystems.auth.data.mongodb.client.repository.LrcAccountRepository;
import com.bithumbsystems.auth.data.mongodb.client.repository.LrcEmailTokenRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Service;
import reactor.core.publisher.Mono;

@Service
@RequiredArgsConstructor
public class LrcAccountDomainService {
    private final LrcAccountRepository repository;
    private final LrcEmailTokenRepository emailTokenRepository;
    /**
     * 사용자 이메일 정보를 통해서 사용자 정보를 조회한다.
     *
     * @param email
     * @return
     */
    public Mono<LrcAccount> findByEmail(String email) {
        return repository.findByEmail(email);
    }

    /**
     * 사용자 정보를 저장한다.
     *
     * @param user
     * @return
     */
    public Mono<LrcAccount> save(LrcAccount user) {
        return repository.save(user);
    }

    /**
     * 사용자 키를 통해서 사용자 정보를 리턴한다.
     * @param id
     * @return
     */
    public Mono<LrcAccount> findById(String id) {
        return repository.findById(id);
    }
    public Mono<LrcEmailToken> getEmailToken(String id) {
        return emailTokenRepository.findById(id);
    }
    public Mono<LrcEmailToken> updateEmailToken(LrcEmailToken token) {
        return emailTokenRepository.save(token);
    }
}
