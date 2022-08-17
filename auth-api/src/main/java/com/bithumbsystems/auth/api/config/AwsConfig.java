package com.bithumbsystems.auth.api.config;

import static software.amazon.awssdk.services.kms.model.EncryptionAlgorithmSpec.RSAES_OAEP_SHA_256;

import com.amazonaws.encryptionsdk.AwsCrypto;
import com.amazonaws.encryptionsdk.CommitmentPolicy;
import com.amazonaws.encryptionsdk.CryptoAlgorithm;
import com.amazonaws.encryptionsdk.kms.KmsMasterKeyProvider;
import com.bithumbsystems.auth.api.config.properties.AwsProperties;
import java.net.URI;
import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.util.concurrent.CompletableFuture;
import javax.annotation.PostConstruct;
import lombok.Data;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.apache.commons.codec.binary.Base64;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;
import reactor.core.publisher.Mono;
import software.amazon.awssdk.auth.credentials.ProfileCredentialsProvider;
import software.amazon.awssdk.core.SdkBytes;
import software.amazon.awssdk.regions.Region;
import software.amazon.awssdk.services.kms.KmsAsyncClient;
import software.amazon.awssdk.services.kms.model.DecryptRequest;
import software.amazon.awssdk.services.kms.model.EncryptRequest;
import software.amazon.awssdk.services.kms.model.EncryptResponse;
import software.amazon.awssdk.services.ses.SesClient;

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
    private KmsAsyncClient kmsAsyncClient;
    private SesClient sesClient;
    @Value("${spring.profiles.active:}")
    private String activeProfiles;

    private com.amazonaws.auth.profile.ProfileCredentialsProvider provider;

    @PostConstruct
    public void init() {
        if (activeProfiles.equals("local") || activeProfiles.equals("default")) {
            kmsAsyncClient = KmsAsyncClient.builder()
                    .region(Region.of(awsProperties.getRegion()))
                    .credentialsProvider(ProfileCredentialsProvider.create(profileName))
                    .endpointOverride(URI.create(awsProperties.getKmsEndPoint()))
                    .build();

            sesClient =  SesClient.builder()
                .region(Region.of(awsProperties.getRegion()))
                .credentialsProvider(ProfileCredentialsProvider.create(profileName))
                .endpointOverride(URI.create(awsProperties.getSesEndPoint()))
                .build();

            provider = new com.amazonaws.auth.profile.ProfileCredentialsProvider(profileName);
        }else { // dev, prod
            kmsAsyncClient = KmsAsyncClient.builder()
                    .region(Region.of(awsProperties.getRegion()))
                    .endpointOverride(URI.create(awsProperties.getKmsEndPoint()))
                    .build();

            sesClient =  SesClient.builder()
                .region(Region.of(awsProperties.getRegion()))
                .endpointOverride(URI.create(awsProperties.getSesEndPoint()))
                .build();
        }
    }

    public String encryptAes256(String content) {
        log.debug("kms-00");
        String data = null;
        try {
            AwsCrypto crypto = AwsCrypto.builder()
                    .withCommitmentPolicy(CommitmentPolicy.ForbidEncryptAllowDecrypt)
                    .withEncryptionAlgorithm(CryptoAlgorithm. ALG_AES_256_GCM_IV12_TAG16_NO_KDF)
                    .build();
            log.debug("kms-01");
            log.debug(kmsKey);
            KmsMasterKeyProvider prov = KmsMasterKeyProvider.builder()
                    .withCredentials(provider)
                    .buildStrict(kmsKey);
            log.debug("kms-02");
            byte[] chiperText = crypto.encryptData(prov, content.getBytes(StandardCharsets.UTF_8)).getResult();
            log.debug("kms-03");
            data = new String(Base64.encodeBase64(chiperText), StandardCharsets.UTF_8);
            log.debug("kms-04");
        }catch(Exception ex) {
            ex.printStackTrace();
        }
        return data;
    }

    /**
     * KMS 호출에서 Mono type으로 리턴한다.
     *
     * @param contents
     * @return
     */
    public Mono<String> encryptMono(final String contents) {

        log.debug("encryptMono data => {}, {}", kmsKey, contents);
        ByteBuffer buffer = ByteBuffer.wrap(Base64.encodeBase64(contents.getBytes(StandardCharsets.UTF_8)));
        EncryptRequest request = EncryptRequest.builder()
                .keyId(kmsKey)
                .plaintext(SdkBytes.fromByteBuffer(buffer))  // SdkBytes.fromByteArray(contents.getBytes(StandardCharsets.UTF_8)))
                .build();

        return Mono.fromFuture(
                kmsAsyncClient.encrypt(request)
                        .whenComplete((resp, err) -> {
                            try {
                                if (resp != null) {
                                    log.info("kms success. Details {}", resp);
                                }else {
                                    log.error("whenComplete error : {}", err);
                                    err.printStackTrace();
                                }
                            }finally {
                               //kmsAsyncClient.close();
                            }
                        })
                        .thenApply(res -> {
                            String s = null;
                            try {

                                ByteBuffer buf = res.ciphertextBlob().asByteBuffer();
                                byte[] b1 = new byte[buf.remaining()];
                                buf.get(b1);
                                String data = new String(Base64.encodeBase64(b1), StandardCharsets.UTF_8);
                                log.debug("encoded data : {}", data);

                                return data;

//                                ByteBuffer buf = res.ciphertextBlob().asByteBuffer();
//                                s = new String(buf.array(), StandardCharsets.UTF_8);
//
//                                //byte[] buffer = res.ciphertextBlob().asByteArray();
//                                //String data = new String(buffer, StandardCharsets.UTF_8);
//                                log.debug("encrypt result => ");
//                                log.debug(s);
//                                return s;
                            }catch(Exception ex) {
                                ex.printStackTrace();
                            }
                            return s;
                        })
        );
    }
    /**
     * KMS 호출해서 데이터를 암호화한다.
     *
     * @param contents
     * @return
     */
    public String encrypt(final String contents) {



        log.debug("encrypt data => {}{}", kmsKey, contents);
        ByteBuffer buffer = ByteBuffer.wrap(contents.getBytes(StandardCharsets.UTF_8));  // Base64.encodeBase64(contents.getBytes(StandardCharsets.UTF_8)));
        EncryptRequest request = EncryptRequest.builder()
                .keyId(kmsKey)
                .encryptionAlgorithm(RSAES_OAEP_SHA_256)
                .plaintext(SdkBytes.fromByteBuffer(buffer)) // contents.getBytes(StandardCharsets.UTF_8)))
                .build();

        CompletableFuture<EncryptResponse> encryptData = kmsAsyncClient.encrypt(request);

        String result = encryptData.thenApply(encryptResponse -> {
            ByteBuffer buf = encryptResponse.ciphertextBlob().asByteBuffer();
            byte[] b1 = new byte[buf.remaining()];
            buf.get(b1);
            String data = new String(Base64.encodeBase64(b1), StandardCharsets.UTF_8);
            log.debug("encoded data : {}", data);

            return data;
//
//            byte[] buffer = encryptResponse.ciphertextBlob().asByteArray();
//            String data = new String(buffer, StandardCharsets.UTF_8);
//            log.debug(data);
//            return data;
        }).join();
        log.debug("==============================");
        log.debug(result);
        log.debug("==============================");

        return result;


//                kmsAsyncClient.encrypt(request)
//                    .thenApply(response -> {
//                        log.debug("response : {}", response);
//                        byte[] buffer = response.ciphertextBlob().asByteArray();
//
//                        //ByteBuffer buf = response.ciphertextBlob().asByteBuffer();
//                        //byte[] b1 = new byte[buf.remaining()];
//                        //buf.get(b1);
//                        String data = new String(buffer, StandardCharsets.UTF_8);
//                        log.debug("encoded data : {}", data);
//                        return data;  // new String(b1, StandardCharsets.UTF_8);
//                        //return ByteBuffer.wrap(response.ciphertextBlob().asByteArray() ciphertextBlob().asByteArray(StandardCharsets.UTF_8) .asByteArray() .asUtf8String();
//                    });
//
//

//                    .whenComplete((res, error) -> {
//                        try {
//                            if (res != null) {
//                                log.debug("kms encrypt whenComplete : {}", res);
//                            }else {
//                                error.printStackTrace();
//                            }
//                        }finally {
//
//                        }
//                    });

//        String result = encryptData.thenApply(res -> {
//            log.debug("===============================");
//            log.debug("result => {}", res);
//            log.debug("===============================");
//            return res;
//        }).join();
//
//        log.debug("encryptData result => {}", result);
//
//        return result;

        //return encryptData.thenApply(result->log.debug(result)).join();
    }

    /**
     * KMS 호출해서 데이터를 복호화 한다.
     *
     * @param contents
     * @return
     */
    public String decrypt(final String contents) {
        log.debug("decrypt data => {}", contents);
        DecryptRequest decryptRequest = DecryptRequest.builder()
                .keyId(kmsKey)
                .ciphertextBlob(SdkBytes.fromByteArray(contents.getBytes(StandardCharsets.UTF_8)))
                .encryptionAlgorithm(RSAES_OAEP_SHA_256)
                .build();

        CompletableFuture<String> decryptData =
                kmsAsyncClient.decrypt(decryptRequest)
                        .thenApply(response -> {
                            return response.plaintext().asUtf8String();
                        })
                        .whenComplete((res, error) -> {
                            try {
                                if (res != null) {
                                    log.debug("kms decrypt whenComplete : {}", res);
                                }else {
                                    error.printStackTrace();
                                }
                            }finally {

                            }
                        });
        //return decryptData.toString();

        String result = decryptData.thenApply(res -> {
            log.debug("result => {}", res);
            return res;
        }).join();
        return result;

        //return encryptData.thenApply(result->log.debug(result)).join();

    }
}
