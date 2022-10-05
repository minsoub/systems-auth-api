package com.bithumbsystems.auth.data.authentication.service;

import com.bithumbsystems.auth.data.authentication.entity.RsaCipherInfo;
import com.bithumbsystems.auth.data.authentication.repository.RsaCipherInfoRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Service;
import reactor.core.publisher.Mono;

@Service
@RequiredArgsConstructor
public class RsaCipherInfoDomainService {
    private final RsaCipherInfoRepository repository;

    /**
     * RSA 암호화 키 정보를 저장한다.
     *
     * @param user
     * @return
     */
    public Mono<RsaCipherInfo> save(RsaCipherInfo user) {
        return repository.save(user);
    }

    /**
     * RSA 암호화 키 정보를 리턴한다.
     * @param id
     * @return
     */
    public Mono<RsaCipherInfo> findById(String id) {
        return repository.findById(id);
    }

}
