package uk.gov.di.ipv.core.library.verifiablecredential.service;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.nimbusds.common.contenttype.ContentType;
import com.nimbusds.jwt.SignedJWT;
import com.nimbusds.oauth2.sdk.ParseException;
import com.nimbusds.oauth2.sdk.http.HTTPRequest;
import com.nimbusds.oauth2.sdk.http.HTTPResponse;
import com.nimbusds.oauth2.sdk.token.BearerAccessToken;
import org.apache.http.HttpHeaders;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.apache.logging.log4j.message.StringMapMessage;
import uk.gov.di.ipv.core.library.annotations.ExcludeFromGeneratedCoverageReport;
import uk.gov.di.ipv.core.library.config.ConfigurationVariable;
import uk.gov.di.ipv.core.library.config.EnvironmentVariable;
import uk.gov.di.ipv.core.library.domain.ErrorResponse;
import uk.gov.di.ipv.core.library.dto.CredentialIssuerConfig;
import uk.gov.di.ipv.core.library.exceptions.VerifiableCredentialException;
import uk.gov.di.ipv.core.library.helpers.LogHelper;
import uk.gov.di.ipv.core.library.persistence.DataStore;
import uk.gov.di.ipv.core.library.persistence.item.VcStoreItem;
import uk.gov.di.ipv.core.library.service.ConfigService;
import uk.gov.di.ipv.core.library.verifiablecredential.domain.VerifiableCredentialResponse;
import uk.gov.di.ipv.core.library.verifiablecredential.domain.VerifiableCredentialStatus;
import uk.gov.di.ipv.core.library.verifiablecredential.dto.VerifiableCredentialResponseDto;

import java.io.IOException;
import java.time.Instant;
import java.util.ArrayList;
import java.util.Collections;
import java.util.Date;
import java.util.List;

import static uk.gov.di.ipv.core.library.domain.CriConstants.DCMAW_CRI;
import static uk.gov.di.ipv.core.library.helpers.LogHelper.LogField.LOG_CRI_ID;
import static uk.gov.di.ipv.core.library.helpers.LogHelper.LogField.LOG_MESSAGE_DESCRIPTION;
import static uk.gov.di.ipv.core.library.helpers.LogHelper.LogField.LOG_RESPONSE_CONTENT_TYPE;

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
