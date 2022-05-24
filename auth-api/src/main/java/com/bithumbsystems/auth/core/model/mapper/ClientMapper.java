package com.bithumbsystems.auth.core.model.mapper;

import com.bithumbsystems.auth.core.model.request.ClientRegisterRequest;
import com.bithumbsystems.auth.core.model.response.ClientRegisterResponse;
import com.bithumbsystems.auth.data.mongodb.client.entity.Client;
import org.mapstruct.Mapper;
import org.mapstruct.factory.Mappers;

@Mapper
public interface ClientMapper {

  ClientMapper INSTANCE = Mappers.getMapper(ClientMapper.class);

  Client clientRegisterRequestToClient(ClientRegisterRequest clientRegisterRequest);

  ClientRegisterResponse clientToClientRegisterResponse(Client client);

}
