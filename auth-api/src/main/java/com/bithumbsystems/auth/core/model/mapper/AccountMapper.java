package com.bithumbsystems.auth.core.model.mapper;

import com.bithumbsystems.auth.core.model.request.SignUpRequest;
import com.bithumbsystems.auth.core.model.response.SignUpResponse;
import com.bithumbsystems.auth.data.mongodb.entity.Account;
import org.mapstruct.Mapper;
import org.mapstruct.Mapping;

@Mapper(componentModel = "spring")
public interface AccountMapper {

    @Mapping(target = "isEnabled", ignore = true)
    @Mapping(target = "roles", ignore = true)
    Account requestToEntity(SignUpRequest signUpRequest);

    SignUpResponse entityToResponse(Account account);
}
