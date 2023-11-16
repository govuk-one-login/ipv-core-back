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
import com.nimbusds.oauth2.sdk.auth.ClientAuthentication;
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
import uk.gov.di.ipv.core.library.helpers.JwtHelper;
import uk.gov.di.ipv.core.library.helpers.LogHelper;
import uk.gov.di.ipv.core.library.helpers.SecureTokenHelper;
import uk.gov.di.ipv.core.library.service.ConfigService;
import uk.gov.di.ipv.core.library.service.CriOAuthSessionService;
import uk.gov.di.ipv.core.library.verifiablecredential.domain.VerifiableCredentialResponse;
import uk.gov.di.ipv.core.library.verifiablecredential.domain.VerifiableCredentialStatus;
import uk.gov.di.ipv.core.library.verifiablecredential.dto.VerifiableCredentialResponseDto;
import uk.gov.di.ipv.core.processcricallback.dto.CriCallbackRequest;
import uk.gov.di.ipv.core.processcricallback.exception.CriApiException;

import java.io.IOException;
import java.net.URI;
import java.time.OffsetDateTime;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
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
    private final CriOAuthSessionService criOAuthSessionService;

    @ExcludeFromGeneratedCoverageReport
    public CriApiService(
            ConfigService configService,
            JWSSigner signer,
            CriOAuthSessionService criOAuthSessionService) {
        this.configService = configService;
        this.signer = signer;
        this.criOAuthSessionService = criOAuthSessionService;
    }

    public String getApiKey(CriCallbackRequest callbackRequest) {
        var criOAuthSessionItem =
                criOAuthSessionService.getCriOauthSessionItem(callbackRequest.getState());
        var criConfig = configService.getCriConfig(criOAuthSessionItem);

        return criConfig.getRequiresApiKey()
                ? configService.getCriPrivateApiKey(criOAuthSessionItem)
                : null;
    }

    public BearerAccessToken fetchAccessToken(String apiKey, CriCallbackRequest callbackRequest)
            throws CriApiException {
        var criId = callbackRequest.getCredentialIssuerId();
        var authorisationCode = callbackRequest.getAuthorizationCode();
        var criOAuthSessionItem =
                criOAuthSessionService.getCriOauthSessionItem(callbackRequest.getState());
        var criConfig = configService.getCriConfig(criOAuthSessionItem);

        AuthorizationCode authorizationCode = new AuthorizationCode(authorisationCode);
        try {
            OffsetDateTime dateTime = OffsetDateTime.now();
            ClientAuthClaims clientAuthClaims =
                    new ClientAuthClaims(
                            criConfig.getClientId(),
                            criConfig.getClientId(),
                            criConfig.getComponentId(),
                            dateTime.plusSeconds(
                                            Long.parseLong(
                                                    configService.getSsmParameter(
                                                            ConfigurationVariable.JWT_TTL_SECONDS)))
                                    .toEpochSecond(),
                            SecureTokenHelper.generate());
            SignedJWT signedClientJwt =
                    JwtHelper.createSignedJwtFromObject(clientAuthClaims, signer);

            ClientAuthentication clientAuthentication = new PrivateKeyJWT(signedClientJwt);

            URI redirectionUri = criConfig.getClientCallbackUrl();

            TokenRequest tokenRequest =
                    new TokenRequest(
                            criConfig.getTokenUrl(),
                            clientAuthentication,
                            new AuthorizationCodeGrant(authorizationCode, redirectionUri));

            HTTPRequest httpRequest = tokenRequest.toHTTPRequest();
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
                        criId,
                        criConfig.getTokenUrl(),
                        errorObject.getCode(),
                        errorObject.getDescription(),
                        errorObject.getHTTPStatusCode());
                throw new CriApiException(
                        HTTPResponse.SC_BAD_REQUEST, ErrorResponse.INVALID_TOKEN_REQUEST);
            }

            BearerAccessToken token =
                    tokenResponse.toSuccessResponse().getTokens().getBearerAccessToken();
            LOGGER.info("Auth Code exchanged for Access Token.");
            return token;
        } catch (IOException | ParseException | JOSEException e) {
            LOGGER.error("Error exchanging token: {}", e.getMessage(), e);
            throw new CriApiException(
                    HTTPResponse.SC_SERVER_ERROR,
                    ErrorResponse.FAILED_TO_EXCHANGE_AUTHORIZATION_CODE);
        }
    }

    public VerifiableCredentialResponse fetchVerifiableCredential(
            BearerAccessToken accessToken, String apiKey, CriCallbackRequest callbackRequest)
            throws CriApiException {
        var criId = callbackRequest.getCredentialIssuerId();
        var criOAuthSessionItem =
                criOAuthSessionService.getCriOauthSessionItem(callbackRequest.getState());
        var criConfig = configService.getCriConfig(criOAuthSessionItem);

        HTTPRequest credentialRequest =
                new HTTPRequest(HTTPRequest.Method.POST, criConfig.getCredentialUrl());

        if (apiKey != null) {
            LOGGER.info(
                    new StringMapMessage()
                            .with(
                                    LOG_MESSAGE_DESCRIPTION.getFieldName(),
                                    "CRI has API key, sending key in header for credential request.")
                            .with(LOG_CRI_ID.getFieldName(), criId));
            credentialRequest.setHeader(API_KEY_HEADER, apiKey);
        }

        credentialRequest.setAuthorization(accessToken.toAuthorizationHeader());

        try {
            HTTPResponse response = credentialRequest.send();
            if (!response.indicatesSuccess()) {
                LogHelper.logErrorMessage(
                        "Error retrieving credential",
                        response.getStatusCode(),
                        response.getStatusMessage());
                if (criId.equals(DCMAW_CRI)
                        && response.getStatusCode() == HTTPResponse.SC_NOT_FOUND) {
                    throw new CriApiException(
                            HTTPResponse.SC_NOT_FOUND,
                            ErrorResponse.FAILED_TO_GET_CREDENTIAL_FROM_ISSUER);
                }
                throw new CriApiException(
                        HTTPResponse.SC_SERVER_ERROR,
                        ErrorResponse.FAILED_TO_GET_CREDENTIAL_FROM_ISSUER);
            }

            String responseContentType = response.getHeaderValue(HttpHeaders.CONTENT_TYPE);
            if (ContentType.APPLICATION_JWT.matches(ContentType.parse(responseContentType))) {
                SignedJWT vcJwt = (SignedJWT) response.getContentAsJWT();
                VerifiableCredentialResponse verifiableCredentialResponse =
                        VerifiableCredentialResponse.builder()
                                .verifiableCredentials(Collections.singletonList(vcJwt))
                                .build();
                LOGGER.info("Verifiable Credential retrieved from JWT response.");
                return verifiableCredentialResponse;
            } else if (ContentType.APPLICATION_JSON.matches(
                    ContentType.parse(responseContentType))) {
                VerifiableCredentialResponse verifiableCredentialResponse =
                        getVerifiableCredentialResponseForApplicationJson(response.getContent());
                LOGGER.info("Verifiable Credential retrieved from json response.");
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
            LogHelper.logErrorMessage("Error retrieving credential.", e.getMessage());
            throw new CriApiException(
                    HTTPResponse.SC_SERVER_ERROR,
                    ErrorResponse.FAILED_TO_GET_CREDENTIAL_FROM_ISSUER);
        }
    }

    private VerifiableCredentialResponse getVerifiableCredentialResponseForApplicationJson(
            String responseString) throws JsonProcessingException, java.text.ParseException {
        VerifiableCredentialResponseDto verifiableCredentialResponse =
                OBJECT_MAPPER.readValue(responseString, VerifiableCredentialResponseDto.class);
        VerifiableCredentialResponse.VerifiableCredentialResponseBuilder
                verifiableCredentialResponseBuilder =
                        VerifiableCredentialResponse.builder()
                                .userId(verifiableCredentialResponse.getUserId());
        if (verifiableCredentialResponse.getVerifiableCredentials() != null) {
            List<SignedJWT> vcJwts = new ArrayList<>();
            for (String vc : verifiableCredentialResponse.getVerifiableCredentials()) {
                vcJwts.add(SignedJWT.parse(vc));
            }
            verifiableCredentialResponseBuilder.verifiableCredentials(vcJwts);
        }
        if (verifiableCredentialResponse.getCredentialStatus() != null) {
            verifiableCredentialResponseBuilder.credentialStatus(
                    VerifiableCredentialStatus.fromStatusString(
                            verifiableCredentialResponse.getCredentialStatus()));
        }
        return verifiableCredentialResponseBuilder.build();
    }
}
