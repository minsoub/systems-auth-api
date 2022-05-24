package com.bithumbsystems.auth.api.config.datasource;

import com.mongodb.ConnectionString;
import com.mongodb.MongoClientSettings;
import com.mongodb.reactivestreams.client.MongoClient;
import com.mongodb.reactivestreams.client.MongoClients;
import java.io.ByteArrayInputStream;
import java.io.File;
import java.io.InputStream;
import java.nio.file.Files;
import java.security.KeyStore;
import java.security.cert.CertificateFactory;
import java.util.Arrays;
import java.util.stream.Collectors;
import javax.net.ssl.SSLContext;
import javax.net.ssl.TrustManagerFactory;
import lombok.RequiredArgsConstructor;
import lombok.SneakyThrows;
import lombok.extern.slf4j.Slf4j;
import org.apache.commons.io.FileUtils;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.Profile;
import org.springframework.core.io.ClassPathResource;
import org.springframework.data.mongodb.config.AbstractReactiveMongoConfiguration;

@Slf4j
@Configuration
@Profile("dev|prod")
@RequiredArgsConstructor
public class MongoConfig extends AbstractReactiveMongoConfiguration {

    private final ParameterStoreConfig config;

    @Override
    protected String getDatabaseName() {
        return config.getMongoProperties().getMongodbName();
    }

    @Override
    public MongoClient reactiveMongoClient() {
        log.info("Applying AWS DocumentDB Configuration");
        MongoClientSettings settings = configureClientSettings();
        return MongoClients.create(settings);
    }

    @SneakyThrows
    protected MongoClientSettings configureClientSettings() {
        MongoClientSettings.Builder builder = MongoClientSettings.builder();
        builder.applyConnectionString(getConnectionString());

        var endOfCertificateDelimiter = "-----END CERTIFICATE-----";
        //File resource = resourceLoader.getResource("classpath:cert/rds-combined-ca-bundle.pem").getFile();  // new ClassPathResource("cert/rds-combined-ca-bundle.pem").getFile();

        ClassPathResource resources = new ClassPathResource("cert/rds-combined-ca-bundle.pem");
        InputStream inputStream = resources.getInputStream();
        File resource = File.createTempFile("rds-combined-ca-bundle", "pem");

        try {
            FileUtils.copyInputStreamToFile(inputStream, resource);
        }finally {
            inputStream.close();
        }

        String pemContents = new String(Files.readAllBytes(resource.toPath()));
        var allCertificates = Arrays.stream(pemContents
                .split(endOfCertificateDelimiter))
            .filter(line -> !line.isBlank())
            .map(line -> line + endOfCertificateDelimiter)
            .collect(Collectors.toUnmodifiableList());

        var certificateFactory = CertificateFactory.getInstance("X.509");
        var keyStore = KeyStore.getInstance(KeyStore.getDefaultType());
        // This allows us to use an in-memory key-store
        keyStore.load(null);

        for (int i = 0; i < allCertificates.size(); i++) {
            var certString = allCertificates.get(i);
            var caCert = certificateFactory.generateCertificate(new ByteArrayInputStream(certString.getBytes()));
            keyStore.setCertificateEntry(String.format("AWS-certificate-%s", i), caCert);
        }

        var trustManagerFactory = TrustManagerFactory.getInstance(TrustManagerFactory.getDefaultAlgorithm());
        trustManagerFactory.init(keyStore);

        var sslContext = SSLContext.getInstance("TLS");
        sslContext.init(null, trustManagerFactory.getTrustManagers(), null);

        builder.applyToSslSettings(ssl -> ssl.enabled(true).context(sslContext));

        return builder.build();
    }

    private ConnectionString getConnectionString() {
        String str = String.format("mongodb://%s:%s@%s:%s/%s?replicaSet=rs0&readPreference=secondaryPreferred&retryWrites=false",
            config.getMongoProperties().getMongodbUser(),
            config.getMongoProperties().getMongodbPassword(),
            config.getMongoProperties().getMongodbUrl(),
            config.getMongoProperties().getMongodbPort(),
            config.getMongoProperties().getMongodbName()
        );

        return new ConnectionString(str);
    }
}