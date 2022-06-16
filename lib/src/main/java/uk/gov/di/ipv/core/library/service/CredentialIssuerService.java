package uk.gov.di.ipv.core.library.service;

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
import org.apache.http.client.utils.URIBuilder;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import uk.gov.di.ipv.core.library.annotations.ExcludeFromGeneratedCoverageReport;
import uk.gov.di.ipv.core.library.domain.ClientAuthClaims;
import uk.gov.di.ipv.core.library.domain.CredentialIssuerException;
import uk.gov.di.ipv.core.library.domain.ErrorResponse;
import uk.gov.di.ipv.core.library.dto.CredentialIssuerConfig;
import uk.gov.di.ipv.core.library.dto.CredentialIssuerRequestDto;
import uk.gov.di.ipv.core.library.helpers.JwtHelper;
import uk.gov.di.ipv.core.library.persistence.DataStore;
import uk.gov.di.ipv.core.library.persistence.item.UserIssuedCredentialsItem;

import java.io.IOException;
import java.net.URI;
import java.net.URISyntaxException;
import java.time.LocalDateTime;
import java.time.OffsetDateTime;
import java.util.Objects;
import java.util.UUID;

import static uk.gov.di.ipv.core.library.config.ConfigurationVariable.CORE_FRONT_CALLBACK_URL;
import static uk.gov.di.ipv.core.library.config.ConfigurationVariable.JWT_TTL_SECONDS;
import static uk.gov.di.ipv.core.library.config.EnvironmentVariable.USER_ISSUED_CREDENTIALS_TABLE_NAME;

public class CredentialIssuerService {

    private static final Logger LOGGER = LoggerFactory.getLogger(CredentialIssuerService.class);
    private static final String API_KEY_HEADER = "x-api-key";

    private final DataStore<UserIssuedCredentialsItem> dataStore;
    private final ConfigurationService configurationService;
    private final JWSSigner signer;

    @ExcludeFromGeneratedCoverageReport
    public CredentialIssuerService(ConfigurationService configurationService, JWSSigner signer) {
        this.configurationService = configurationService;
        this.signer = signer;
        boolean isRunningLocally = this.configurationService.isRunningLocally();
        this.dataStore =
                new DataStore<>(
                        this.configurationService.getEnvironmentVariable(
                                USER_ISSUED_CREDENTIALS_TABLE_NAME),
                        UserIssuedCredentialsItem.class,
                        DataStore.getClient(isRunningLocally),
                        isRunningLocally,
                        configurationService);
    }

    public CredentialIssuerService(
            DataStore<UserIssuedCredentialsItem> dataStore,
            ConfigurationService configurationService,
            JWSSigner signer) {
        this.configurationService = configurationService;
        this.signer = signer;
        this.dataStore = dataStore;
    }

    public BearerAccessToken exchangeCodeForToken(
            CredentialIssuerRequestDto request, CredentialIssuerConfig config, String apiKey) {

        AuthorizationCode authorizationCode = new AuthorizationCode(request.getAuthorizationCode());
        try {
            OffsetDateTime dateTime = OffsetDateTime.now();
            ClientAuthClaims clientAuthClaims =
                    new ClientAuthClaims(
                            config.getIpvClientId(),
                            config.getIpvClientId(),
                            config.getAudienceForClients(),
                            dateTime.plusSeconds(
                                            Long.parseLong(
                                                    configurationService.get(JWT_TTL_SECONDS)))
                                    .toEpochSecond(),
                            UUID.randomUUID().toString());
            SignedJWT signedClientJwt =
                    JwtHelper.createSignedJwtFromObject(clientAuthClaims, signer);

            ClientAuthentication clientAuthentication = new PrivateKeyJWT(signedClientJwt);

            String coreFrontCallbackUrl = configurationService.get(CORE_FRONT_CALLBACK_URL);

            TokenRequest tokenRequest =
                    new TokenRequest(
                            config.getTokenUrl(),
                            clientAuthentication,
                            new AuthorizationCodeGrant(
                                    authorizationCode,
                                    getRedirectionUri(config.getId(), coreFrontCallbackUrl)));

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
            return tokenResponse.toSuccessResponse().getTokens().getBearerAccessToken();
        } catch (IOException | ParseException | JOSEException | URISyntaxException e) {
            LOGGER.error("Error exchanging token: {}", e.getMessage(), e);
            throw new CredentialIssuerException(
                    HTTPResponse.SC_SERVER_ERROR,
                    ErrorResponse.FAILED_TO_EXCHANGE_AUTHORIZATION_CODE);
        }
    }

    public SignedJWT getVerifiableCredential(
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

            return (SignedJWT) response.getContentAsJWT();

        } catch (IOException | ParseException e) {
            LOGGER.error("Error retrieving credential: {}", e.getMessage());
            throw new CredentialIssuerException(
                    HTTPResponse.SC_SERVER_ERROR,
                    ErrorResponse.FAILED_TO_GET_CREDENTIAL_FROM_ISSUER);
        }
    }

    public void persistUserCredentials(String credential, CredentialIssuerRequestDto request) {
        UserIssuedCredentialsItem userIssuedCredentials = new UserIssuedCredentialsItem();
        userIssuedCredentials.setIpvSessionId(request.getIpvSessionId());
        userIssuedCredentials.setCredentialIssuer(request.getCredentialIssuerId());
        userIssuedCredentials.setCredential(credential);
        userIssuedCredentials.setDateCreated(LocalDateTime.now());
        try {
            dataStore.create(userIssuedCredentials);
        } catch (UnsupportedOperationException e) {
            LOGGER.error("Error persisting user credential: {}", e.getMessage(), e);
            throw new CredentialIssuerException(
                    HTTPResponse.SC_SERVER_ERROR, ErrorResponse.FAILED_TO_SAVE_CREDENTIAL);
        }
    }

    private static URI getRedirectionUri(String criId, String coreFrontCallbackUrl)
            throws URISyntaxException {
        URIBuilder uriBuilder = new URIBuilder(coreFrontCallbackUrl).addParameter("id", criId);
        return uriBuilder.build();
    }
}
