package com.bithumbsystems.auth;

import io.swagger.v3.oas.annotations.OpenAPIDefinition;
import io.swagger.v3.oas.annotations.info.Info;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.EnableAutoConfiguration;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.boot.autoconfigure.data.mongo.MongoDataAutoConfiguration;
import org.springframework.boot.autoconfigure.mongo.MongoAutoConfiguration;
import org.springframework.boot.autoconfigure.mongo.MongoReactiveAutoConfiguration;
import org.springframework.boot.autoconfigure.mongo.embedded.EmbeddedMongoAutoConfiguration;
import org.springframework.boot.context.properties.ConfigurationPropertiesScan;
import org.springframework.context.annotation.Profile;

@SpringBootApplication
@ConfigurationPropertiesScan
@OpenAPIDefinition(info = @Info(title = "Auth API", version = "1.0", description = "Auth APIs v1.0"))
public class AuthAPIApplication {

    public static void main(String[] args) {
        SpringApplication.run(AuthAPIApplication.class, args);
    }

    @Profile("dev|prod|eks-dev")
    @EnableAutoConfiguration(
        exclude = {
            MongoAutoConfiguration.class,
            MongoReactiveAutoConfiguration.class,
            MongoDataAutoConfiguration.class,
            EmbeddedMongoAutoConfiguration.class
        })
    static class WithoutAutoConfigurationMongo{}
}
