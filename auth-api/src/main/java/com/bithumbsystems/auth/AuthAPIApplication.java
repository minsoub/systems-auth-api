package com.bithumbsystems.auth;

import io.swagger.v3.oas.annotations.OpenAPIDefinition;
import io.swagger.v3.oas.annotations.info.Info;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.data.mongodb.repository.config.EnableMongoRepositories;
import org.springframework.web.reactive.config.EnableWebFlux;

@SpringBootApplication
@EnableWebFlux
@EnableMongoRepositories("com.bithumbsystems.auth.data.mongodb")
@OpenAPIDefinition(info = @Info(title = "Auth API", version = "1.0", description = "Auth APIs v1.0"))
public class AuthAPIApplication {

    public static void main(String[] args) {
        SpringApplication.run(AuthAPIApplication.class, args);
    }
}
