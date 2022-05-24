package com.bithumbsystems.auth.data.mongodb.client.service;

import com.bithumbsystems.auth.data.mongodb.client.entity.Client;
import com.bithumbsystems.auth.data.mongodb.client.repository.ClientRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Service;
import reactor.core.publisher.Mono;

@Service
@RequiredArgsConstructor
public class ClientDomainService {

  private ClientRepository clientRepository;

  public Mono<Client> save(Client client) {
    return clientRepository.save(client);
  }

}
