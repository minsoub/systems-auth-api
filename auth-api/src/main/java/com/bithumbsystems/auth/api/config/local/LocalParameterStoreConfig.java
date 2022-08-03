package com.bithumbsystems.auth.api.config.local;

import com.bithumbsystems.auth.api.config.AwsConfig;
import com.bithumbsystems.auth.api.config.property.AwsProperties;
import com.bithumbsystems.auth.api.config.property.MongoProperties;
import com.bithumbsystems.auth.api.config.property.RedisProperties;
import lombok.Data;
import lombok.extern.log4j.Log4j2;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.Profile;
import software.amazon.awssdk.regions.Region;
import software.amazon.awssdk.services.ssm.SsmClient;
import software.amazon.awssdk.services.ssm.model.GetParameterRequest;
import software.amazon.awssdk.services.ssm.model.GetParameterResponse;

import javax.annotation.PostConstruct;

import static com.bithumbsystems.auth.api.config.constant.ParameterStoreConstant.*;

@Log4j2
@Data
@Profile("local|default")
@Configuration
public class LocalParameterStoreConfig {

    private SsmClient ssmClient;
    private MongoProperties mongoProperties;
    private RedisProperties redisProperties;
    private final AwsProperties awsProperties;
    private final CredentialsProvider credentialsProvider;

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
                .credentialsProvider(credentialsProvider.getProvider()) // 로컬에서 개발로 붙을때 사용
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
        this.awsConfig.setCryptoKey(getParameterValue(awsProperties.getParamStoreCryptoName().trim(), CRYPT_ALIAS_NAME));
        log.debug(">> CryptoKey:{}", this.awsConfig.getCryptoKey());
        this.awsConfig.setLrcCryptoKey(getParameterValue(awsProperties.getParamStoreLrcName().trim(), LRC_CRYPT_ALIAS_NAME));
        log.debug(">> LrcCryptoKey:{}", this.awsConfig.getLrcCryptoKey());
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
