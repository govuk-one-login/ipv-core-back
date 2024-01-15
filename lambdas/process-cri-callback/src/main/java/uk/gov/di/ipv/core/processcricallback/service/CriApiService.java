package uk.gov.di.ipv.core.processcricallback.service;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
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
import com.nimbusds.oauth2.sdk.auth.PrivateKeyJWT;
import com.nimbusds.oauth2.sdk.http.HTTPRequest;
import com.nimbusds.oauth2.sdk.http.HTTPResponse;
import com.nimbusds.oauth2.sdk.token.BearerAccessToken;
import org.apache.http.HttpHeaders;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.apache.logging.log4j.message.StringMapMessage;
import uk.gov.di.ipv.core.library.annotations.ExcludeFromGeneratedCoverageReport;
import uk.gov.di.ipv.core.library.config.ConfigurationVariable;
import uk.gov.di.ipv.core.library.domain.ClientAuthClaims;
import uk.gov.di.ipv.core.library.domain.ErrorResponse;
import uk.gov.di.ipv.core.library.dto.CredentialIssuerConfig;
import uk.gov.di.ipv.core.library.dto.CriCallbackRequest;
import uk.gov.di.ipv.core.library.helpers.JwtHelper;
import uk.gov.di.ipv.core.library.helpers.LogHelper;
import uk.gov.di.ipv.core.library.helpers.SecureTokenHelper;
import uk.gov.di.ipv.core.library.persistence.item.CriOAuthSessionItem;
import uk.gov.di.ipv.core.library.service.ConfigService;
import uk.gov.di.ipv.core.library.verifiablecredential.domain.VerifiableCredentialResponse;
import uk.gov.di.ipv.core.library.verifiablecredential.domain.VerifiableCredentialStatus;
import uk.gov.di.ipv.core.library.verifiablecredential.dto.VerifiableCredentialResponseDto;
import uk.gov.di.ipv.core.processcricallback.exception.CriApiException;

import java.io.IOException;
import java.time.Clock;
import java.time.OffsetDateTime;
import java.util.ArrayList;
import java.util.Collections;
import java.util.Objects;

import static uk.gov.di.ipv.core.library.domain.CriConstants.DCMAW_CRI;
import static uk.gov.di.ipv.core.library.helpers.LogHelper.LogField.LOG_CRI_ID;
import static uk.gov.di.ipv.core.library.helpers.LogHelper.LogField.LOG_MESSAGE_DESCRIPTION;
import static uk.gov.di.ipv.core.library.helpers.LogHelper.LogField.LOG_RESPONSE_CONTENT_TYPE;

public class CriApiService {
    private static final Logger LOGGER = LogManager.getLogger();
    private static final String API_KEY_HEADER = "x-api-key";
    private static final ObjectMapper OBJECT_MAPPER = new ObjectMapper();
    private final ConfigService configService;
    private final JWSSigner signer;
    private final SecureTokenHelper secureTokenHelper;
    private final Clock clock;

    @ExcludeFromGeneratedCoverageReport
    public CriApiService(
            ConfigService configService,
            JWSSigner signer,
            SecureTokenHelper secureTokenHelper,
            Clock clock) {
        this.configService = configService;
        this.signer = signer;
        this.secureTokenHelper = secureTokenHelper;
        this.clock = clock;
    }

    private String getApiKey(
            CredentialIssuerConfig criConfig, CriOAuthSessionItem criOAuthSessionItem) {
        return criConfig.getRequiresApiKey()
                ? configService.getCriPrivateApiKey(criOAuthSessionItem)
                : null;
    }

    public BearerAccessToken fetchAccessToken(
            CriCallbackRequest callbackRequest, CriOAuthSessionItem criOAuthSessionItem)
            throws CriApiException {
        var criId = callbackRequest.getCredentialIssuerId();
        var criConfig = configService.getCriConfig(criOAuthSessionItem);

        try {
            var httpRequest = buildFetchAccessTokenRequest(callbackRequest, criOAuthSessionItem);
            var httpResponse = httpRequest.send();
            var tokenResponse = TokenResponse.parse(httpResponse);

            if (tokenResponse instanceof TokenErrorResponse) {
                var errorResponse = tokenResponse.toErrorResponse();
                var errorObject =
                        Objects.requireNonNullElse(
                                errorResponse.getErrorObject(),
                                new ErrorObject("unknown", "unknown"));
                LOGGER.error(
                        "Failed to exchange token with credential issuer with ID '{}' at '{}'. Code: '{}', Description: {}, HttpStatus code: {}",
                        criId,
                        criConfig.getTokenUrl(),
                        errorObject.getCode(),
                        errorObject.getDescription(),
                        errorObject.getHTTPStatusCode());
                throw new CriApiException(
                        HTTPResponse.SC_BAD_REQUEST, ErrorResponse.INVALID_TOKEN_REQUEST);
            }

            var token = tokenResponse.toSuccessResponse().getTokens().getBearerAccessToken();
            LOGGER.info(LogHelper.buildLogMessage("Auth Code exchanged for Access Token."));
            return token;
        } catch (IOException | ParseException e) {
            LOGGER.error("Error exchanging token: {}", e.getMessage(), e);
            throw new CriApiException(
                    HTTPResponse.SC_SERVER_ERROR,
                    ErrorResponse.FAILED_TO_EXCHANGE_AUTHORIZATION_CODE);
        }
    }

    public HTTPRequest buildFetchAccessTokenRequest(
            CriCallbackRequest callbackRequest, CriOAuthSessionItem criOAuthSessionItem)
            throws CriApiException {
        var criId = callbackRequest.getCredentialIssuerId();
        var authorisationCode = callbackRequest.getAuthorizationCode();
        var criConfig = configService.getCriConfig(criOAuthSessionItem);
        var apiKey = getApiKey(criConfig, criOAuthSessionItem);
        var authorizationCode = new AuthorizationCode(authorisationCode);

        try {
            var dateTime = OffsetDateTime.now(clock);
            var clientAuthClaims =
                    new ClientAuthClaims(
                            criConfig.getClientId(),
                            criConfig.getClientId(),
                            criConfig.getComponentId(),
                            dateTime.plusSeconds(
                                            Long.parseLong(
                                                    configService.getSsmParameter(
                                                            ConfigurationVariable.JWT_TTL_SECONDS)))
                                    .toEpochSecond(),
                            secureTokenHelper.generate());
            var signedClientJwt = JwtHelper.createSignedJwtFromObject(clientAuthClaims, signer);
            var clientAuthentication = new PrivateKeyJWT(signedClientJwt);
            var redirectionUri = criConfig.getClientCallbackUrl();

            var tokenRequest =
                    new TokenRequest(
                            criConfig.getTokenUrl(),
                            clientAuthentication,
                            new AuthorizationCodeGrant(authorizationCode, redirectionUri));

            var httpRequest = tokenRequest.toHTTPRequest();
            if (apiKey != null) {
                var message =
                        new StringMapMessage()
                                .with(
                                        LOG_MESSAGE_DESCRIPTION.getFieldName(),
                                        "CRI has API key, sending key in header for token request.")
                                .with(LOG_CRI_ID.getFieldName(), criId);
                LOGGER.info(message);
                httpRequest.setHeader(API_KEY_HEADER, apiKey);
            }

            return httpRequest;
        } catch (JOSEException e) {
            LOGGER.error("Error exchanging token: {}", e.getMessage(), e);
            throw new CriApiException(
                    HTTPResponse.SC_SERVER_ERROR,
                    ErrorResponse.FAILED_TO_EXCHANGE_AUTHORIZATION_CODE);
        }
    }

    public VerifiableCredentialResponse fetchVerifiableCredential(
            BearerAccessToken accessToken,
            CriCallbackRequest callbackRequest,
            CriOAuthSessionItem criOAuthSessionItem)
            throws CriApiException {
        var criId = callbackRequest.getCredentialIssuerId();
        var credentialRequest =
                buildFetchVerifiableCredentialRequest(
                        accessToken, callbackRequest, criOAuthSessionItem);

        try {
            var response = credentialRequest.send();

            if (!response.indicatesSuccess()) {
                LOGGER.error(
                        LogHelper.buildErrorMessage(
                                "Error retrieving credential",
                                response.getStatusMessage(),
                                response.getStatusCode()));
                if (DCMAW_CRI.equals(criId)
                        && response.getStatusCode() == HTTPResponse.SC_NOT_FOUND) {
                    throw new CriApiException(
                            HTTPResponse.SC_NOT_FOUND,
                            ErrorResponse.FAILED_TO_GET_CREDENTIAL_FROM_ISSUER);
                }
                throw new CriApiException(
                        HTTPResponse.SC_SERVER_ERROR,
                        ErrorResponse.FAILED_TO_GET_CREDENTIAL_FROM_ISSUER);
            }

            var responseContentType = response.getHeaderValue(HttpHeaders.CONTENT_TYPE);
            if (ContentType.APPLICATION_JWT.matches(ContentType.parse(responseContentType))) {
                var vcJwt = (SignedJWT) response.getContentAsJWT();
                var verifiableCredentialResponse =
                        VerifiableCredentialResponse.builder()
                                .verifiableCredentials(Collections.singletonList(vcJwt))
                                .build();
                LOGGER.info(
                        LogHelper.buildLogMessage(
                                "Verifiable Credential retrieved from JWT response."));
                return verifiableCredentialResponse;
            } else if (ContentType.APPLICATION_JSON.matches(
                    ContentType.parse(responseContentType))) {
                var verifiableCredentialResponse =
                        getVerifiableCredentialResponseForApplicationJson(response.getContent());
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
        } catch (IOException | ParseException | java.text.ParseException e) {
            LOGGER.error(LogHelper.buildErrorMessage("Error retrieving credential.", e));
            throw new CriApiException(
                    HTTPResponse.SC_SERVER_ERROR,
                    ErrorResponse.FAILED_TO_GET_CREDENTIAL_FROM_ISSUER);
        }
    }

    public HTTPRequest buildFetchVerifiableCredentialRequest(
            BearerAccessToken accessToken,
            CriCallbackRequest callbackRequest,
            CriOAuthSessionItem criOAuthSessionItem) {
        var criId = callbackRequest.getCredentialIssuerId();
        var criConfig = configService.getCriConfig(criOAuthSessionItem);
        var apiKey = getApiKey(criConfig, criOAuthSessionItem);

        var request = new HTTPRequest(HTTPRequest.Method.POST, criConfig.getCredentialUrl());

        if (apiKey != null) {
            LOGGER.info(
                    new StringMapMessage()
                            .with(
                                    LOG_MESSAGE_DESCRIPTION.getFieldName(),
                                    "CRI has API key, sending key in header for credential request.")
                            .with(LOG_CRI_ID.getFieldName(), criId));
            request.setHeader(API_KEY_HEADER, apiKey);
        }

        request.setAuthorization(accessToken.toAuthorizationHeader());

        return request;
    }

    private VerifiableCredentialResponse getVerifiableCredentialResponseForApplicationJson(
            String responseString) throws JsonProcessingException, java.text.ParseException {
        var vcResponse =
                OBJECT_MAPPER.readValue(responseString, VerifiableCredentialResponseDto.class);
        var vcResponseBuilder =
                VerifiableCredentialResponse.builder().userId(vcResponse.getUserId());
        if (vcResponse.getVerifiableCredentials() != null) {
            var vcJwts = new ArrayList<SignedJWT>();
            for (var vc : vcResponse.getVerifiableCredentials()) {
                vcJwts.add(SignedJWT.parse(vc));
            }
            vcResponseBuilder.verifiableCredentials(vcJwts);
        }
        if (vcResponse.getCredentialStatus() != null) {
            vcResponseBuilder.credentialStatus(
                    VerifiableCredentialStatus.fromStatusString(vcResponse.getCredentialStatus()));
        }
        return vcResponseBuilder.build();
    }
}
