package uk.gov.di.ipv.core.library.criapiservice;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.nimbusds.common.contenttype.ContentType;
import com.nimbusds.jose.JOSEException;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.oauth2.sdk.AuthorizationCode;
import com.nimbusds.oauth2.sdk.AuthorizationCodeGrant;
import com.nimbusds.oauth2.sdk.AuthorizationGrant;
import com.nimbusds.oauth2.sdk.ClientCredentialsGrant;
import com.nimbusds.oauth2.sdk.ErrorObject;
import com.nimbusds.oauth2.sdk.ParseException;
import com.nimbusds.oauth2.sdk.TokenErrorResponse;
import com.nimbusds.oauth2.sdk.TokenRequest;
import com.nimbusds.oauth2.sdk.TokenResponse;
import com.nimbusds.oauth2.sdk.auth.ClientAuthentication;
import com.nimbusds.oauth2.sdk.auth.ClientSecretBasic;
import com.nimbusds.oauth2.sdk.auth.PrivateKeyJWT;
import com.nimbusds.oauth2.sdk.auth.Secret;
import com.nimbusds.oauth2.sdk.http.HTTPRequest;
import com.nimbusds.oauth2.sdk.http.HTTPRequestSender;
import com.nimbusds.oauth2.sdk.http.HTTPResponse;
import com.nimbusds.oauth2.sdk.id.ClientID;
import com.nimbusds.oauth2.sdk.token.BearerAccessToken;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.apache.logging.log4j.message.StringMapMessage;
import uk.gov.di.ipv.core.library.annotations.ExcludeFromGeneratedCoverageReport;
import uk.gov.di.ipv.core.library.config.ConfigurationVariable;
import uk.gov.di.ipv.core.library.criapiservice.dto.AsyncCredentialRequestBodyDto;
import uk.gov.di.ipv.core.library.criapiservice.exception.CriApiException;
import uk.gov.di.ipv.core.library.domain.Cri;
import uk.gov.di.ipv.core.library.domain.ErrorResponse;
import uk.gov.di.ipv.core.library.dto.CriCallbackRequest;
import uk.gov.di.ipv.core.library.dto.OauthCriConfig;
import uk.gov.di.ipv.core.library.helpers.JwtHelper;
import uk.gov.di.ipv.core.library.helpers.LogHelper;
import uk.gov.di.ipv.core.library.helpers.SecureTokenHelper;
import uk.gov.di.ipv.core.library.persistence.item.CriOAuthSessionItem;
import uk.gov.di.ipv.core.library.service.ConfigService;
import uk.gov.di.ipv.core.library.signing.SignerFactory;
import uk.gov.di.ipv.core.library.tracing.TracingHttpClient;
import uk.gov.di.ipv.core.library.verifiablecredential.domain.VerifiableCredentialResponse;
import uk.gov.di.ipv.core.library.verifiablecredential.domain.VerifiableCredentialStatus;
import uk.gov.di.ipv.core.library.verifiablecredential.dto.VerifiableCredentialResponseDto;

import java.io.IOException;
import java.time.Clock;
import java.time.Instant;
import java.util.Collections;
import java.util.Date;
import java.util.Objects;

import static uk.gov.di.ipv.core.library.config.EnvironmentVariable.ENVIRONMENT;
import static uk.gov.di.ipv.core.library.domain.Cri.DCMAW;
import static uk.gov.di.ipv.core.library.domain.Cri.DWP_KBV;
import static uk.gov.di.ipv.core.library.helpers.LogHelper.LogField.LOG_CRI_ID;
import static uk.gov.di.ipv.core.library.helpers.LogHelper.LogField.LOG_MESSAGE_DESCRIPTION;
import static uk.gov.di.ipv.core.library.helpers.LogHelper.LogField.LOG_RESPONSE_CONTENT_TYPE;

public class CriApiService {
    private static final Logger LOGGER = LogManager.getLogger();
    private static final String API_KEY_HEADER = "x-api-key";
    private static final String HEADER_CONTENT_TYPE = "Content-Type";
    private static final String HEADER_ACCEPT = "Accept";
    private static final String MIME_TYPE_APPLICATION_JSON = "application/json";
    private static final ObjectMapper OBJECT_MAPPER = new ObjectMapper();
    private final ConfigService configService;
    private final SignerFactory signerFactory;
    private final SecureTokenHelper secureTokenHelper;
    private final Clock clock;
    private final HTTPRequestSender httpRequestSender;

    @ExcludeFromGeneratedCoverageReport
    public CriApiService(ConfigService configService) {
        this(
                configService,
                new SignerFactory(configService),
                SecureTokenHelper.getInstance(),
                Clock.systemDefaultZone(),
                new JavaHttpRequestSender(TracingHttpClient.newHttpClient()));
    }

    // Used for contract tests
    public CriApiService(
            ConfigService configService,
            SignerFactory signerFactory,
            SecureTokenHelper secureTokenHelper,
            Clock clock) {
        this(
                configService,
                signerFactory,
                secureTokenHelper,
                clock,
                new JavaHttpRequestSender(TracingHttpClient.newHttpClient()));
    }

    // Used for unit tests
    public CriApiService(
            ConfigService configService,
            SignerFactory signerFactory,
            SecureTokenHelper secureTokenHelper,
            Clock clock,
            HTTPRequestSender httpRequestSender) {
        this.configService = configService;
        this.signerFactory = signerFactory;
        this.secureTokenHelper = secureTokenHelper;
        this.clock = clock;
        this.httpRequestSender = httpRequestSender;
    }

    private String getApiKey(OauthCriConfig criConfig, CriOAuthSessionItem criOAuthSessionItem) {
        return criConfig.isRequiresApiKey()
                ? configService.getSecret(
                        ConfigurationVariable.CREDENTIAL_ISSUER_API_KEY,
                        criOAuthSessionItem.getCriId(),
                        criOAuthSessionItem.getConnection())
                : null;
    }

    public BearerAccessToken fetchAccessToken(
            CriCallbackRequest callbackRequest, CriOAuthSessionItem criOAuthSessionItem)
            throws CriApiException {

        var accessTokenRequest =
                buildAccessTokenRequestWithJwtAuthenticationAndAuthorizationCode(
                        callbackRequest.getAuthorizationCode(), criOAuthSessionItem);

        return fetchAccessToken(accessTokenRequest);
    }

    public BearerAccessToken fetchAccessToken(
            String basicAuthClientId,
            String basicAuthClientSecret,
            CriOAuthSessionItem criOAuthSessionItem)
            throws CriApiException {
        var httpRequest =
                buildAccessTokenRequestWithBasicAuthenticationAndClientCredentials(
                        basicAuthClientId, basicAuthClientSecret, criOAuthSessionItem);

        return fetchAccessToken(httpRequest);
    }

    private BearerAccessToken fetchAccessToken(HTTPRequest accessTokenRequest)
            throws CriApiException {
        try {
            var httpResponse = accessTokenRequest.send(httpRequestSender);
            var tokenResponse = TokenResponse.parse(httpResponse);

            if (tokenResponse instanceof TokenErrorResponse) {
                var errorResponse = tokenResponse.toErrorResponse();
                var errorObject =
                        Objects.requireNonNullElse(
                                errorResponse.getErrorObject(),
                                new ErrorObject("unknown", "unknown"));
                LOGGER.error(
                        LogHelper.buildErrorMessage(
                                "Failed to exchange token with credential issuer", errorObject));
                throw new CriApiException(
                        HTTPResponse.SC_BAD_REQUEST, ErrorResponse.INVALID_TOKEN_REQUEST);
            }

            var token = tokenResponse.toSuccessResponse().getTokens().getBearerAccessToken();
            LOGGER.info(LogHelper.buildLogMessage("Auth Code exchanged for Access Token."));
            return token;
        } catch (IOException | ParseException e) {
            LOGGER.error(LogHelper.buildErrorMessage("Error exchanging token", e));
            throw new CriApiException(
                    HTTPResponse.SC_SERVER_ERROR,
                    ErrorResponse.FAILED_TO_EXCHANGE_AUTHORIZATION_CODE);
        }
    }

    private HTTPRequest buildAccessTokenRequestWithJwtAuthenticationAndAuthorizationCode(
            String authorisationCode, CriOAuthSessionItem criOAuthSessionItem)
            throws CriApiException {
        var criConfig = configService.getOauthCriConfig(criOAuthSessionItem);
        var authorizationCode = new AuthorizationCode(authorisationCode);

        try {
            var clientAuthClaimsSet =
                    new JWTClaimsSet.Builder()
                            .issuer(criConfig.getClientId())
                            .subject(criConfig.getClientId())
                            .audience(criConfig.getComponentId())
                            .expirationTime(
                                    Date.from(
                                            Instant.now(clock)
                                                    .plusSeconds(configService.getJwtTtlSeconds())))
                            .jwtID(secureTokenHelper.generate())
                            .build();

            var signedClientJwt =
                    JwtHelper.createSignedJwt(clientAuthClaimsSet, signerFactory.getSigner());
            var clientAuthentication = new PrivateKeyJWT(signedClientJwt);
            var redirectionUri = criConfig.getClientCallbackUrl();
            var authorizationGrant = new AuthorizationCodeGrant(authorizationCode, redirectionUri);

            return buildAccessTokenRequest(
                    criOAuthSessionItem, clientAuthentication, authorizationGrant);
        } catch (JOSEException e) {
            LOGGER.error("Error exchanging token: {}", e.getMessage(), e);
            throw new CriApiException(
                    HTTPResponse.SC_SERVER_ERROR,
                    ErrorResponse.FAILED_TO_EXCHANGE_AUTHORIZATION_CODE);
        }
    }

    private HTTPRequest buildAccessTokenRequestWithBasicAuthenticationAndClientCredentials(
            String basicAuthClientId,
            String basicAuthClientSecret,
            CriOAuthSessionItem criOAuthSessionItem) {

        var clientAuthentication =
                new ClientSecretBasic(
                        new ClientID(basicAuthClientId), new Secret(basicAuthClientSecret));

        return buildAccessTokenRequest(
                criOAuthSessionItem, clientAuthentication, new ClientCredentialsGrant());
    }

    private HTTPRequest buildAccessTokenRequest(
            CriOAuthSessionItem criOAuthSessionItem,
            ClientAuthentication clientAuthentication,
            AuthorizationGrant authorizationGrant) {
        var criConfig = configService.getOauthCriConfig(criOAuthSessionItem);
        var apiKey = getApiKey(criConfig, criOAuthSessionItem);

        var tokenRequest =
                new TokenRequest(
                        criConfig.getTokenUrl(), clientAuthentication, authorizationGrant, null);

        var httpRequest = tokenRequest.toHTTPRequest();

        if (apiKey != null) {
            LOGGER.info(
                    LogHelper.buildLogMessage(
                            "CRI has API key, sending key in header for token request."));
            httpRequest.setHeader(API_KEY_HEADER, apiKey);
        }

        return httpRequest;
    }

    public VerifiableCredentialResponse fetchVerifiableCredential(
            BearerAccessToken accessToken,
            Cri cri,
            CriOAuthSessionItem criOAuthSessionItem,
            AsyncCredentialRequestBodyDto requestBody)
            throws CriApiException, JsonProcessingException {
        var request =
                buildFetchVerifiableCredentialRequest(
                        accessToken, cri, criOAuthSessionItem, requestBody);

        return fetchVerifiableCredential(cri, request);
    }

    public VerifiableCredentialResponse fetchVerifiableCredential(
            BearerAccessToken accessToken, Cri cri, CriOAuthSessionItem criOAuthSessionItem)
            throws CriApiException, JsonProcessingException {
        var request =
                buildFetchVerifiableCredentialRequest(accessToken, cri, criOAuthSessionItem, null);

        return fetchVerifiableCredential(cri, request);
    }

    private VerifiableCredentialResponse fetchVerifiableCredential(
            Cri cri, HTTPRequest credentialRequest) throws CriApiException {
        try {
            var response = credentialRequest.send(httpRequestSender);
            if (!response.indicatesSuccess()) {
                LOGGER.error(
                        LogHelper.buildErrorMessage(
                                "Error retrieving credential",
                                response.getStatusMessage(),
                                response.getStatusCode()));
                if (DCMAW.equals(cri) && response.getStatusCode() == HTTPResponse.SC_NOT_FOUND) {
                    throw new CriApiException(
                            HTTPResponse.SC_NOT_FOUND,
                            ErrorResponse.FAILED_TO_GET_CREDENTIAL_FROM_ISSUER);
                }
                throw new CriApiException(
                        HTTPResponse.SC_SERVER_ERROR,
                        ErrorResponse.FAILED_TO_GET_CREDENTIAL_FROM_ISSUER);
            }

            var responseContentType = response.getHeaderValue(HEADER_CONTENT_TYPE);

            if (ContentType.APPLICATION_JWT.matches(ContentType.parse(responseContentType))) {
                var verifiableCredentialResponse =
                        VerifiableCredentialResponse.builder()
                                .verifiableCredentials(
                                        Collections.singletonList(response.getBody()))
                                .build();
                LOGGER.info(
                        LogHelper.buildLogMessage(
                                "Verifiable Credential retrieved from JWT response."));
                return verifiableCredentialResponse;
            } else if (ContentType.APPLICATION_JSON.matches(
                    ContentType.parse(responseContentType))) {
                var verifiableCredentialResponse =
                        getVerifiableCredentialResponseForApplicationJson(
                                response.getBody().trim());
                LOGGER.info(
                        LogHelper.buildLogMessage(
                                "Verifiable Credential retrieved from json response."));
                return verifiableCredentialResponse;
            } else {
                LOGGER.error(
                        new StringMapMessage()
                                .with(
                                        LOG_MESSAGE_DESCRIPTION.getFieldName(),
                                        "Error retrieving credential::Unknown response type received from CRI.")
                                .with(
                                        LOG_RESPONSE_CONTENT_TYPE.getFieldName(),
                                        responseContentType));
                throw new CriApiException(
                        HTTPResponse.SC_SERVER_ERROR,
                        ErrorResponse.FAILED_TO_GET_CREDENTIAL_FROM_ISSUER);
            }
        } catch (IOException | java.text.ParseException e) {
            LOGGER.error(LogHelper.buildErrorMessage("Error retrieving credential.", e));
            throw new CriApiException(
                    HTTPResponse.SC_SERVER_ERROR,
                    ErrorResponse.FAILED_TO_GET_CREDENTIAL_FROM_ISSUER);
        }
    }

    private HTTPRequest buildFetchVerifiableCredentialRequest(
            BearerAccessToken accessToken,
            Cri cri,
            CriOAuthSessionItem criOAuthSessionItem,
            AsyncCredentialRequestBodyDto requestBody)
            throws JsonProcessingException {
        var criConfig = configService.getOauthCriConfig(criOAuthSessionItem);
        var apiKey = getApiKey(criConfig, criOAuthSessionItem);

        var request = new HTTPRequest(HTTPRequest.Method.POST, criConfig.getCredentialUrl());

        if (requestBody != null) {
            var bodyString = OBJECT_MAPPER.writeValueAsString(requestBody);
            request.setBody(bodyString);
            request.setHeader(HEADER_CONTENT_TYPE, MIME_TYPE_APPLICATION_JSON);
        } else {
            // Temporary for DWP integration testing
            if (configService.getEnvironmentVariable(ENVIRONMENT) != null
                    && configService.getEnvironmentVariable(ENVIRONMENT).equals("staging")
                    && cri.equals(DWP_KBV)) {
                request.setHeader(HEADER_ACCEPT, "application/jwt");
            } else {
                request.setHeader(
                        HEADER_CONTENT_TYPE,
                        ""); // remove the default, no request body so we don't need a content type
            }
        }

        if (apiKey != null) {
            LOGGER.info(
                    new StringMapMessage()
                            .with(
                                    LOG_MESSAGE_DESCRIPTION.getFieldName(),
                                    "CRI has API key, sending key in header for credential request.")
                            .with(LOG_CRI_ID.getFieldName(), cri.getId()));
            request.setHeader(API_KEY_HEADER, apiKey);
        }

        request.setAuthorization(accessToken.toAuthorizationHeader());

        return request;
    }

    private VerifiableCredentialResponse getVerifiableCredentialResponseForApplicationJson(
            String responseString) throws JsonProcessingException {
        var vcResponse =
                OBJECT_MAPPER.readValue(responseString, VerifiableCredentialResponseDto.class);
        var vcResponseBuilder =
                VerifiableCredentialResponse.builder()
                        .userId(vcResponse.getUserId())
                        .verifiableCredentials(vcResponse.getVerifiableCredentials());
        if (vcResponse.getCredentialStatus() != null) {
            vcResponseBuilder.credentialStatus(
                    VerifiableCredentialStatus.fromStatusString(vcResponse.getCredentialStatus()));
        }
        return vcResponseBuilder.build();
    }
}
