package uk.gov.di.ipv.core.library.credentialissuer;

import com.nimbusds.common.contenttype.ContentType;
import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JWSSigner;
import com.nimbusds.jwt.SignedJWT;
import com.nimbusds.oauth2.sdk.AuthorizationCode;
import com.nimbusds.oauth2.sdk.AuthorizationCodeGrant;
import com.nimbusds.oauth2.sdk.ErrorObject;
import com.nimbusds.oauth2.sdk.ParseException;
import com.nimbusds.oauth2.sdk.TokenErrorResponse;
import com.nimbusds.oauth2.sdk.TokenRequest;
import com.nimbusds.oauth2.sdk.TokenResponse;
import com.nimbusds.oauth2.sdk.auth.ClientAuthentication;
import com.nimbusds.oauth2.sdk.auth.PrivateKeyJWT;
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
import uk.gov.di.ipv.core.library.credentialissuer.exceptions.CredentialIssuerException;
import uk.gov.di.ipv.core.library.domain.ClientAuthClaims;
import uk.gov.di.ipv.core.library.domain.ErrorResponse;
import uk.gov.di.ipv.core.library.domain.UserIdentity;
import uk.gov.di.ipv.core.library.dto.CredentialIssuerConfig;
import uk.gov.di.ipv.core.library.helpers.JwtHelper;
import uk.gov.di.ipv.core.library.helpers.SecureTokenHelper;
import uk.gov.di.ipv.core.library.persistence.DataStore;
import uk.gov.di.ipv.core.library.persistence.item.VcStoreItem;
import uk.gov.di.ipv.core.library.service.ConfigService;

import java.io.IOException;
import java.net.URI;
import java.time.Instant;
import java.time.OffsetDateTime;
import java.util.ArrayList;
import java.util.Collections;
import java.util.Date;
import java.util.List;
import java.util.Objects;

public class CredentialIssuerService {

    private static final Logger LOGGER = LogManager.getLogger();
    private static final String API_KEY_HEADER = "x-api-key";

    private final DataStore<VcStoreItem> dataStore;
    private final ConfigService configService;
    private final JWSSigner signer;

    @ExcludeFromGeneratedCoverageReport
    public CredentialIssuerService(ConfigService configService, JWSSigner signer) {
        this.configService = configService;
        this.signer = signer;
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

    public CredentialIssuerService(
            DataStore<VcStoreItem> dataStore, ConfigService configService, JWSSigner signer) {
        this.configService = configService;
        this.signer = signer;
        this.dataStore = dataStore;
    }

    public BearerAccessToken exchangeCodeForToken(
            String authCode, CredentialIssuerConfig config, String apiKey) {

        AuthorizationCode authorizationCode = new AuthorizationCode(authCode);
        try {
            OffsetDateTime dateTime = OffsetDateTime.now();
            ClientAuthClaims clientAuthClaims =
                    new ClientAuthClaims(
                            config.getIpvClientId(),
                            config.getIpvClientId(),
                            config.getAudienceForClients(),
                            dateTime.plusSeconds(
                                            Long.parseLong(
                                                    configService.getSsmParameter(
                                                            ConfigurationVariable.JWT_TTL_SECONDS)))
                                    .toEpochSecond(),
                            SecureTokenHelper.generate());
            SignedJWT signedClientJwt =
                    JwtHelper.createSignedJwtFromObject(clientAuthClaims, signer);

            ClientAuthentication clientAuthentication = new PrivateKeyJWT(signedClientJwt);

            URI redirectionUri = config.getIpvCoreRedirectUrl();

            TokenRequest tokenRequest =
                    new TokenRequest(
                            config.getTokenUrl(),
                            clientAuthentication,
                            new AuthorizationCodeGrant(authorizationCode, redirectionUri));

            HTTPRequest httpRequest = tokenRequest.toHTTPRequest();
            if (apiKey != null) {
                LOGGER.info(
                        "Private api key found for cri {}, sending key in header for token request",
                        config.getId());
                httpRequest.setHeader(API_KEY_HEADER, apiKey);
            }

            HTTPResponse httpResponse = httpRequest.send();
            TokenResponse tokenResponse = TokenResponse.parse(httpResponse);

            if (tokenResponse instanceof TokenErrorResponse) {
                TokenErrorResponse errorResponse = tokenResponse.toErrorResponse();
                ErrorObject errorObject =
                        Objects.requireNonNullElse(
                                errorResponse.getErrorObject(),
                                new ErrorObject("unknown", "unknown"));
                LOGGER.error(
                        "Failed to exchange token with credential issuer with ID '{}' at '{}'. Code: '{}', Description: {}, HttpStatus code: {}",
                        config.getId(),
                        config.getTokenUrl(),
                        errorObject.getCode(),
                        errorObject.getDescription(),
                        errorObject.getHTTPStatusCode());
                throw new CredentialIssuerException(
                        HTTPResponse.SC_BAD_REQUEST, ErrorResponse.INVALID_TOKEN_REQUEST);
            }

            BearerAccessToken token =
                    tokenResponse.toSuccessResponse().getTokens().getBearerAccessToken();
            LOGGER.info("Auth Code exchanged for Access Token");
            return token;

        } catch (IOException | ParseException | JOSEException e) {
            LOGGER.error("Error exchanging token: {}", e.getMessage(), e);
            throw new CredentialIssuerException(
                    HTTPResponse.SC_SERVER_ERROR,
                    ErrorResponse.FAILED_TO_EXCHANGE_AUTHORIZATION_CODE);
        }
    }

    public List<SignedJWT> getVerifiableCredential(
            BearerAccessToken accessToken, CredentialIssuerConfig config, String apiKey) {
        HTTPRequest credentialRequest =
                new HTTPRequest(HTTPRequest.Method.POST, config.getCredentialUrl());

        if (apiKey != null) {
            LOGGER.info(
                    "Private api key found for cri {}, sending key in header for credential request",
                    config.getId());
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
                throw new CredentialIssuerException(
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
                throw new CredentialIssuerException(
                        HTTPResponse.SC_SERVER_ERROR,
                        ErrorResponse.FAILED_TO_GET_CREDENTIAL_FROM_ISSUER);
            }
        } catch (IOException | ParseException | java.text.ParseException e) {
            LOGGER.error("Error retrieving credential: {}", e.getMessage());
            throw new CredentialIssuerException(
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
            throw new CredentialIssuerException(
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
