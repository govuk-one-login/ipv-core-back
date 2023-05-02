package uk.gov.di.ipv.core.retrievecricredential.service;

import com.nimbusds.common.contenttype.ContentType;
import com.nimbusds.jwt.SignedJWT;
import com.nimbusds.oauth2.sdk.ParseException;
import com.nimbusds.oauth2.sdk.http.HTTPRequest;
import com.nimbusds.oauth2.sdk.http.HTTPResponse;
import com.nimbusds.oauth2.sdk.token.BearerAccessToken;
import net.minidev.json.JSONArray;
import net.minidev.json.JSONObject;
import org.apache.http.HttpHeaders;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import uk.gov.di.ipv.core.library.annotations.ExcludeFromGeneratedCoverageReport;
import uk.gov.di.ipv.core.library.config.ConfigurationVariable;
import uk.gov.di.ipv.core.library.config.EnvironmentVariable;
import uk.gov.di.ipv.core.library.domain.ErrorResponse;
import uk.gov.di.ipv.core.library.domain.UserIdentity;
import uk.gov.di.ipv.core.library.dto.CredentialIssuerConfig;
import uk.gov.di.ipv.core.library.persistence.DataStore;
import uk.gov.di.ipv.core.library.persistence.item.VcStoreItem;
import uk.gov.di.ipv.core.library.service.ConfigService;
import uk.gov.di.ipv.core.retrievecricredential.exception.VerifiableCredentialException;

import java.io.IOException;
import java.time.Instant;
import java.util.ArrayList;
import java.util.Collections;
import java.util.Date;
import java.util.List;

public class VerifiableCredentialService {

    private static final Logger LOGGER = LogManager.getLogger();
    private static final String API_KEY_HEADER = "x-api-key";

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

    public List<SignedJWT> getVerifiableCredential(
            BearerAccessToken accessToken,
            CredentialIssuerConfig config,
            String apiKey,
            String credentialIssuerId) {
        HTTPRequest credentialRequest =
                new HTTPRequest(HTTPRequest.Method.POST, config.getCredentialUrl());

        if (apiKey != null) {
            LOGGER.info(
                    "CRI {} has API key, sending key in header for credential request",
                    credentialIssuerId);
            credentialRequest.setHeader(API_KEY_HEADER, apiKey);
        }

        credentialRequest.setAuthorization(accessToken.toAuthorizationHeader());

        try {
            HTTPResponse response = credentialRequest.send();
            if (!response.indicatesSuccess()) {
                LOGGER.error(
                        "Error retrieving credential: {} - {}",
                        response.getStatusCode(),
                        response.getStatusMessage());
                throw new VerifiableCredentialException(
                        HTTPResponse.SC_SERVER_ERROR,
                        ErrorResponse.FAILED_TO_GET_CREDENTIAL_FROM_ISSUER);
            }

            String responseContentType = response.getHeaderValue(HttpHeaders.CONTENT_TYPE);
            if (ContentType.APPLICATION_JWT.matches(ContentType.parse(responseContentType))) {
                SignedJWT vcJwt = (SignedJWT) response.getContentAsJWT();
                LOGGER.info("Verifiable Credential retrieved");
                return Collections.singletonList(vcJwt);
            } else if (ContentType.APPLICATION_JSON.matches(
                    ContentType.parse(responseContentType))) {
                JSONObject vcJson = response.getContentAsJSONObject();

                JSONArray vcArray = (JSONArray) vcJson.get(UserIdentity.VCS_CLAIM_NAME);
                List<SignedJWT> vcJwts = new ArrayList<>();
                for (Object vc : vcArray) {
                    vcJwts.add(SignedJWT.parse(vc.toString()));
                }

                LOGGER.info("Verifiable Credential retrieved");
                return vcJwts;
            } else {
                LOGGER.error(
                        "Error retrieving credential: Unknown response type received from CRI - {}",
                        responseContentType);
                throw new VerifiableCredentialException(
                        HTTPResponse.SC_SERVER_ERROR,
                        ErrorResponse.FAILED_TO_GET_CREDENTIAL_FROM_ISSUER);
            }
        } catch (IOException | ParseException | java.text.ParseException e) {
            LOGGER.error("Error retrieving credential: {}", e.getMessage());
            throw new VerifiableCredentialException(
                    HTTPResponse.SC_SERVER_ERROR,
                    ErrorResponse.FAILED_TO_GET_CREDENTIAL_FROM_ISSUER);
        }
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
