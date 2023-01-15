package com.bithumbsystems.auth.api.config;

import com.amazonaws.client.builder.AwsClientBuilder;
import com.amazonaws.services.sqs.AmazonSQSAsync;
import com.amazonaws.services.sqs.AmazonSQSAsyncClientBuilder;
import com.bithumbsystems.auth.api.config.properties.AwsProperties;
import java.net.URI;
import javax.annotation.PostConstruct;
import javax.mail.Transport;
import lombok.Data;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.stereotype.Component;
import software.amazon.awssdk.auth.credentials.ProfileCredentialsProvider;
import software.amazon.awssdk.regions.Region;
import software.amazon.awssdk.services.kms.KmsAsyncClient;

@Slf4j
@Data
@Component
@RequiredArgsConstructor
public class AwsConfig {

  private final AwsProperties awsProperties;
  @Value("${cloud.aws.credentials.profile-name}")
  private String profileName;
  private String kmsKey;
  private String saltKey;
  private String ivKey;
  private String cryptoKey;
  private String lrcCryptoKey;
  private String cpcCryptoKey;
  private KmsAsyncClient kmsAsyncClient;
  private Transport transport;
  @Value("${spring.profiles.active:}")
  private String activeProfiles;

  private com.amazonaws.auth.profile.ProfileCredentialsProvider provider;

  @PostConstruct
  public void init() {
    if (activeProfiles.equals("local") || activeProfiles.equals("localstack") || activeProfiles.equals("default")) {
      kmsAsyncClient = KmsAsyncClient.builder()
          .region(Region.of(awsProperties.getRegion()))
          .credentialsProvider(ProfileCredentialsProvider.create(profileName))
          .endpointOverride(URI.create(awsProperties.getKmsEndPoint()))
          .build();
      provider = new com.amazonaws.auth.profile.ProfileCredentialsProvider(profileName);
    } else { // dev, prod
      kmsAsyncClient = KmsAsyncClient.builder()
          .region(Region.of(awsProperties.getRegion()))
          .endpointOverride(URI.create(awsProperties.getKmsEndPoint()))
          .build();
    }
  }

  @Bean
  public AmazonSQSAsync amazonSQS() {
    var endpointConfig = new AwsClientBuilder.EndpointConfiguration(
        awsProperties.getSqsEndPoint(),
        awsProperties.getRegion()
    );
    if (activeProfiles.equals("local") || activeProfiles.equals("localstack") || activeProfiles.equals("default")) {
      return AmazonSQSAsyncClientBuilder.standard()
          .withCredentials(provider)
          .withEndpointConfiguration(endpointConfig)
          .build();
    } else {
      return AmazonSQSAsyncClientBuilder.standard()
          .withEndpointConfiguration(endpointConfig)
          .build();
    }
  }
}
