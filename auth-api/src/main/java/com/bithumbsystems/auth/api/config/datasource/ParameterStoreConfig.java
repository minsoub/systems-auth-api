package com.bithumbsystems.auth.api.config.datasource;

import static com.bithumbsystems.auth.api.config.constant.ParameterStoreConstant.CRYPT_ALIAS_NAME;
import static com.bithumbsystems.auth.api.config.constant.ParameterStoreConstant.DB_NAME;
import static com.bithumbsystems.auth.api.config.constant.ParameterStoreConstant.DB_PASSWORD;
import static com.bithumbsystems.auth.api.config.constant.ParameterStoreConstant.DB_PORT;
import static com.bithumbsystems.auth.api.config.constant.ParameterStoreConstant.DB_URL;
import static com.bithumbsystems.auth.api.config.constant.ParameterStoreConstant.DB_USER;
import static com.bithumbsystems.auth.api.config.constant.ParameterStoreConstant.JWT_ACCESS_EXPIRATION;
import static com.bithumbsystems.auth.api.config.constant.ParameterStoreConstant.JWT_REFRESH_EXPIRATION;
import static com.bithumbsystems.auth.api.config.constant.ParameterStoreConstant.JWT_SECRET_KEY;
import static com.bithumbsystems.auth.api.config.constant.ParameterStoreConstant.KMS_ALIAS_NAME;
import static com.bithumbsystems.auth.api.config.constant.ParameterStoreConstant.LRC_CRYPT_ALIAS_NAME;
import static com.bithumbsystems.auth.api.config.constant.ParameterStoreConstant.MAIL_SENDER;
import static com.bithumbsystems.auth.api.config.constant.ParameterStoreConstant.REDIS_HOST;
import static com.bithumbsystems.auth.api.config.constant.ParameterStoreConstant.REDIS_PORT;
import static com.bithumbsystems.auth.api.config.constant.ParameterStoreConstant.REDIS_TOKEN;

import com.bithumbsystems.auth.api.config.AwsConfig;
import com.bithumbsystems.auth.api.config.properties.AwsProperties;
import com.bithumbsystems.auth.api.config.properties.JwtProperties;
import com.bithumbsystems.auth.api.config.properties.MongoProperties;
import com.bithumbsystems.auth.api.config.properties.RedisProperties;
import javax.annotation.PostConstruct;
import lombok.Data;
import lombok.extern.log4j.Log4j2;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.Profile;
import software.amazon.awssdk.regions.Region;
import software.amazon.awssdk.services.ssm.SsmClient;
import software.amazon.awssdk.services.ssm.model.GetParameterRequest;
import software.amazon.awssdk.services.ssm.model.GetParameterResponse;

@Log4j2
@Data
@Profile("dev|prod|eks-dev")
@Configuration
public class ParameterStoreConfig {

    private SsmClient ssmClient;
    private MongoProperties mongoProperties;
    private RedisProperties redisProperties;
    private final AwsProperties awsProperties;

    private final JwtProperties jwtProperties;

    private final AwsConfig awsConfig;


    @Value("${cloud.aws.credentials.profile-name}")
    private String profileName;

    @PostConstruct
    public void init() {

        log.debug("config store [prefix] => {}", awsProperties.getPrefix());
        log.debug("config store [doc name] => {}", awsProperties.getParamStoreDocName());
        log.debug("config store [redis name] => {}", awsProperties.getParamStoreRedisName());
        log.debug("config store [kms name] => {}", awsProperties.getParamStoreKmsName());

        this.ssmClient = SsmClient.builder()
            //.credentialsProvider(credentialsProvider.getProvider()) // 로컬에서 개발로 붙을때 사용
            .region(Region.of(awsProperties.getRegion()))
            .build();

        this.mongoProperties = new MongoProperties(
            getParameterValue(awsProperties.getParamStoreDocName(), DB_URL),
            getParameterValue(awsProperties.getParamStoreDocName(), DB_USER),
            getParameterValue(awsProperties.getParamStoreDocName(), DB_PASSWORD),
            getParameterValue(awsProperties.getParamStoreDocName(), DB_PORT),
            getParameterValue(awsProperties.getParamStoreDocName(), DB_NAME)
        );

        this.redisProperties = new RedisProperties(
            getParameterValue(awsProperties.getParamStoreRedisName(), REDIS_HOST),
            getParameterValue(awsProperties.getParamStoreRedisName(), REDIS_PORT),
            getParameterValue(awsProperties.getParamStoreRedisName(), REDIS_TOKEN)
        );

        // KMS Parameter Key
        this.awsConfig.setKmsKey(getParameterValue(awsProperties.getParamStoreKmsName(), KMS_ALIAS_NAME));
        this.awsConfig.setSaltKey(getParameterValue(awsProperties.getParamStoreSaltName(), KMS_ALIAS_NAME));
        this.awsConfig.setIvKey(getParameterValue(awsProperties.getParamStoreIvName(), KMS_ALIAS_NAME));
        this.awsConfig.setCryptoKey(getParameterValue(awsProperties.getParamStoreCryptoName().trim(), CRYPT_ALIAS_NAME));
        this.awsConfig.setLrcCryptoKey(getParameterValue(awsProperties.getParamStoreLrcName().trim(), LRC_CRYPT_ALIAS_NAME));
        this.awsProperties.setEmailSender(getParameterValue(awsProperties.getParamStoreMessageName(), MAIL_SENDER));

        this.jwtProperties.setSecret(getParameterValue(awsProperties.getParamStoreAuthName(), JWT_SECRET_KEY));
        this.jwtProperties.setAccessExpiration(getParameterValue(awsProperties.getParamStoreAuthName(), JWT_ACCESS_EXPIRATION));
        this.jwtProperties.setRefreshExpiration(getParameterValue(awsProperties.getParamStoreAuthName(), JWT_REFRESH_EXPIRATION));
    }

    protected String getParameterValue(String storeName, String type) {
        String parameterName = String.format("%s/%s_%s/%s", awsProperties.getPrefix(), storeName, profileName, type);

        GetParameterRequest request = GetParameterRequest.builder()
            .name(parameterName)
            .withDecryption(true)
            .build();

        GetParameterResponse response = this.ssmClient.getParameter(request);

        return response.parameter().value();
    }
}
