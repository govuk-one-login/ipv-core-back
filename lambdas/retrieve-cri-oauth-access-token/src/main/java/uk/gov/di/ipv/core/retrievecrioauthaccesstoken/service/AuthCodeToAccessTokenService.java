package uk.gov.di.ipv.core.retrievecrioauthaccesstoken.service;

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
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.apache.logging.log4j.message.StringMapMessage;
import uk.gov.di.ipv.core.library.annotations.ExcludeFromGeneratedCoverageReport;
import uk.gov.di.ipv.core.library.config.ConfigurationVariable;
import uk.gov.di.ipv.core.library.domain.ClientAuthClaims;
import uk.gov.di.ipv.core.library.domain.ErrorResponse;
import uk.gov.di.ipv.core.library.dto.CredentialIssuerConfig;
import uk.gov.di.ipv.core.library.helpers.JwtHelper;
import uk.gov.di.ipv.core.library.helpers.SecureTokenHelper;
import uk.gov.di.ipv.core.library.service.ConfigService;
import uk.gov.di.ipv.core.retrievecrioauthaccesstoken.exception.AuthCodeToAccessTokenException;

import java.io.IOException;
import java.net.URI;
import java.time.OffsetDateTime;
import java.util.Objects;

import static uk.gov.di.ipv.core.library.helpers.LogHelper.LogField.LOG_CRI_ID;
import static uk.gov.di.ipv.core.library.helpers.LogHelper.LogField.LOG_MESSAGE_DESCRIPTION;

public class AuthCodeToAccessTokenService {

    private static final Logger LOGGER = LogManager.getLogger();
    private static final String API_KEY_HEADER = "x-api-key";

    private final ConfigService configService;
    private final JWSSigner signer;

    @ExcludeFromGeneratedCoverageReport
    public AuthCodeToAccessTokenService(ConfigService configService, JWSSigner signer) {
        this.configService = configService;
        this.signer = signer;
    }

    public BearerAccessToken exchangeCodeForToken(
            String authCode,
            CredentialIssuerConfig config,
            String apiKey,
            String credentialIssuerId) {

        AuthorizationCode authorizationCode = new AuthorizationCode(authCode);
        try {
            OffsetDateTime dateTime = OffsetDateTime.now();
            ClientAuthClaims clientAuthClaims =
                    new ClientAuthClaims(
                            config.getClientId(),
                            config.getClientId(),
                            config.getComponentId(),
                            dateTime.plusSeconds(
                                            Long.parseLong(
                                                    configService.getSsmParameter(
                                                            ConfigurationVariable.JWT_TTL_SECONDS)))
                                    .toEpochSecond(),
                            SecureTokenHelper.generate());
            SignedJWT signedClientJwt =
                    JwtHelper.createSignedJwtFromObject(clientAuthClaims, signer);

            ClientAuthentication clientAuthentication = new PrivateKeyJWT(signedClientJwt);

            URI redirectionUri = config.getClientCallbackUrl();

            TokenRequest tokenRequest =
                    new TokenRequest(
                            config.getTokenUrl(),
                            clientAuthentication,
                            new AuthorizationCodeGrant(authorizationCode, redirectionUri));

            HTTPRequest httpRequest = tokenRequest.toHTTPRequest();
            if (apiKey != null) {
                var message =
                        new StringMapMessage()
                                .with(
                                        LOG_MESSAGE_DESCRIPTION.getFieldName(),
                                        "CRI has API key, sending key in header for token request.")
                                .with(LOG_CRI_ID.getFieldName(), credentialIssuerId);
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
                        credentialIssuerId,
                        config.getTokenUrl(),
                        errorObject.getCode(),
                        errorObject.getDescription(),
                        errorObject.getHTTPStatusCode());
                throw new AuthCodeToAccessTokenException(
                        HTTPResponse.SC_BAD_REQUEST, ErrorResponse.INVALID_TOKEN_REQUEST);
            }

            BearerAccessToken token =
                    tokenResponse.toSuccessResponse().getTokens().getBearerAccessToken();
            LOGGER.info("Auth Code exchanged for Access Token.");
            return token;
        } catch (IOException | ParseException | JOSEException e) {
            LOGGER.error("Error exchanging token: {}", e.getMessage(), e);
            throw new AuthCodeToAccessTokenException(
                    HTTPResponse.SC_SERVER_ERROR,
                    ErrorResponse.FAILED_TO_EXCHANGE_AUTHORIZATION_CODE);
        }
    }
}
