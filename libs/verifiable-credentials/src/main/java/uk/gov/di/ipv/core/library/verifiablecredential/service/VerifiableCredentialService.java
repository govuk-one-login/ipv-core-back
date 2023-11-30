package uk.gov.di.ipv.core.library.verifiablecredential.service;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.nimbusds.jwt.SignedJWT;
import com.nimbusds.oauth2.sdk.http.HTTPResponse;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import uk.gov.di.ipv.core.library.annotations.ExcludeFromGeneratedCoverageReport;
import uk.gov.di.ipv.core.library.config.ConfigurationVariable;
import uk.gov.di.ipv.core.library.config.EnvironmentVariable;
import uk.gov.di.ipv.core.library.domain.ErrorResponse;
import uk.gov.di.ipv.core.library.exceptions.VerifiableCredentialException;
import uk.gov.di.ipv.core.library.persistence.DataStore;
import uk.gov.di.ipv.core.library.persistence.item.VcStoreItem;
import uk.gov.di.ipv.core.library.service.ConfigService;

import java.time.Instant;
import java.util.Date;

public class VerifiableCredentialService {

    private static final Logger LOGGER = LogManager.getLogger();
    private static final String API_KEY_HEADER = "x-api-key";

    private static final ObjectMapper OBJECT_MAPPER = new ObjectMapper();

    private final DataStore<VcStoreItem> dataStore;
    private final ConfigService configService;

    @ExcludeFromGeneratedCoverageReport
    public VerifiableCredentialService(ConfigService configService) {
        this.configService = configService;
        boolean isRunningLocally = this.configService.isRunningLocally();
        this.dataStore =
                new DataStore<>(
                        this.configService.getEnvironmentVariable(
                                EnvironmentVariable.USER_ISSUED_CREDENTIALS_TABLE_NAME),
                        VcStoreItem.class,
                        DataStore.getClient(isRunningLocally),
                        isRunningLocally,
                        configService);
    }

    public VerifiableCredentialService(
            DataStore<VcStoreItem> dataStore, ConfigService configService) {
        this.configService = configService;
        this.dataStore = dataStore;
    }

    public void persistUserCredentials(
            SignedJWT credential, String credentialIssuerId, String userId) {
        try {
            VcStoreItem vcStoreItem = createVcStoreItem(credential, credentialIssuerId, userId);
            dataStore.create(vcStoreItem, ConfigurationVariable.VC_TTL);
        } catch (Exception e) {
            LOGGER.error("Error persisting user credential: {}", e.getMessage(), e);
            throw new VerifiableCredentialException(
                    HTTPResponse.SC_SERVER_ERROR, ErrorResponse.FAILED_TO_SAVE_CREDENTIAL);
        }
    }

    private VcStoreItem createVcStoreItem(
            SignedJWT credential, String credentialIssuerId, String userId)
            throws java.text.ParseException {
        VcStoreItem vcStoreItem =
                VcStoreItem.builder()
                        .userId(userId)
                        .credentialIssuer(credentialIssuerId)
                        .dateCreated(Instant.now())
                        .credential(credential.serialize())
                        .build();

        Date expirationTime = credential.getJWTClaimsSet().getExpirationTime();
        if (expirationTime != null) {
            vcStoreItem.setExpirationTime(expirationTime.toInstant());
        }
        return vcStoreItem;
    }
}
