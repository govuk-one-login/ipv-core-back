package uk.gov.di.ipv.core.library.service;

import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JWSSigner;
import com.nimbusds.jose.crypto.ECDSAVerifier;
import com.nimbusds.jose.crypto.impl.ECDSA;
import com.nimbusds.jose.util.Base64URL;
import com.nimbusds.jwt.JWTClaimNames;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.PlainJWT;
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
import com.nimbusds.openid.connect.sdk.OIDCTokenResponseParser;
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
import java.time.LocalDateTime;
import java.time.OffsetDateTime;
import java.util.Objects;

import static com.nimbusds.jose.JWSAlgorithm.ES256;

public class CredentialIssuerService {

    private static final Logger LOGGER = LoggerFactory.getLogger(CredentialIssuerService.class);

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
                        this.configurationService.getUserIssuedCredentialTableName(),
                        UserIssuedCredentialsItem.class,
                        DataStore.getClient(isRunningLocally),
                        isRunningLocally);
    }

    // used for testing
    public CredentialIssuerService(
            DataStore<UserIssuedCredentialsItem> dataStore,
            ConfigurationService configurationService,
            JWSSigner signer) {
        this.configurationService = configurationService;
        this.signer = signer;
        this.dataStore = dataStore;
    }

    public BearerAccessToken exchangeCodeForToken(
            CredentialIssuerRequestDto request, CredentialIssuerConfig config) {

        AuthorizationCode authorizationCode = new AuthorizationCode(request.getAuthorizationCode());
        try {
            OffsetDateTime dateTime = OffsetDateTime.now();
            ClientAuthClaims clientAuthClaims =
                    new ClientAuthClaims(
                            config.getIpvClientId(),
                            config.getIpvClientId(),
                            configurationService.getClientAudience(config.getId()),
                            dateTime.plusSeconds(
                                            Long.parseLong(configurationService.getIpvTokenTtl()))
                                    .toEpochSecond());
            SignedJWT signedClientJwt =
                    JwtHelper.createSignedJwtFromObject(clientAuthClaims, signer);

            ClientAuthentication clientAuthentication = new PrivateKeyJWT(signedClientJwt);

            TokenRequest tokenRequest =
                    new TokenRequest(
                            config.getTokenUrl(),
                            clientAuthentication,
                            new AuthorizationCodeGrant(
                                    authorizationCode, URI.create(request.getRedirectUri())));

            HTTPResponse httpResponse = tokenRequest.toHTTPRequest().send();
            TokenResponse tokenResponse = parseTokenResponse(httpResponse);

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
        } catch (IOException | ParseException | JOSEException e) {
            LOGGER.error("Error exchanging token: {}", e.getMessage(), e);
            throw new CredentialIssuerException(
                    HTTPResponse.SC_SERVER_ERROR,
                    ErrorResponse.FAILED_TO_EXCHANGE_AUTHORIZATION_CODE);
        }
    }

    public String getVerifiableCredential(
            BearerAccessToken accessToken, CredentialIssuerConfig config, String subject) {
        String requestJWT =
                new PlainJWT(
                                new JWTClaimsSet.Builder()
                                        .claim(
                                                JWTClaimNames.SUBJECT,
                                                String.format("urn:uuid:%s", subject))
                                        .build())
                        .serialize();

        HTTPRequest credentialRequest =
                new HTTPRequest(HTTPRequest.Method.POST, config.getCredentialUrl());
        credentialRequest.setAuthorization(accessToken.toAuthorizationHeader());
        credentialRequest.setQuery(requestJWT);

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

            SignedJWT verifiableCredential = (SignedJWT) response.getContentAsJWT();

            // Signatures from AWS are in DER format. Nimbus needs then in concat format.
            if (signatureIsDerFormat(verifiableCredential)) {
                LOGGER.info("Transcoding signature");
                verifiableCredential = transcodeSignature(verifiableCredential);
            }

            if (!verifiableCredential.verify(new ECDSAVerifier(config.getVcVerifyingPublicJwk()))) {
                LOGGER.error("Verifiable credential signature not valid");
                throw new CredentialIssuerException(
                        HTTPResponse.SC_SERVER_ERROR,
                        ErrorResponse.FAILED_TO_VALIDATE_VERIFIABLE_CREDENTIAL);
            }

            return verifiableCredential.serialize();

        } catch (IOException | ParseException e) {
            LOGGER.error("Error retrieving credential: {}", e.getMessage());
            throw new CredentialIssuerException(
                    HTTPResponse.SC_SERVER_ERROR,
                    ErrorResponse.FAILED_TO_GET_CREDENTIAL_FROM_ISSUER);
        } catch (JOSEException e) {
            LOGGER.error("JOSE exception when verifying signature: {}", e.getMessage());
            throw new CredentialIssuerException(
                    HTTPResponse.SC_SERVER_ERROR,
                    ErrorResponse.FAILED_TO_VALIDATE_VERIFIABLE_CREDENTIAL);
        } catch (java.text.ParseException e) {
            LOGGER.error("Error parsing credential issuer public JWK: {}", e.getMessage());
            throw new CredentialIssuerException(
                    HTTPResponse.SC_SERVER_ERROR, ErrorResponse.FAILED_TO_PARSE_JWK);
        }
    }

    private TokenResponse parseTokenResponse(HTTPResponse httpResponse) throws ParseException {
        return OIDCTokenResponseParser.parse(httpResponse);
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

    private SignedJWT transcodeSignature(SignedJWT vc)
            throws JOSEException, java.text.ParseException {
        Base64URL transcodedSignatureBase64 =
                Base64URL.encode(
                        ECDSA.transcodeSignatureToConcat(
                                vc.getSignature().decode(),
                                ECDSA.getSignatureByteArrayLength(ES256)));
        String[] jwtParts = vc.serialize().split("\\.");
        return SignedJWT.parse(
                String.format("%s.%s.%s", jwtParts[0], jwtParts[1], transcodedSignatureBase64));
    }

    private boolean signatureIsDerFormat(SignedJWT signedJWT) throws JOSEException {
        return signedJWT.getSignature().decode().length != ECDSA.getSignatureByteArrayLength(ES256);
    }
}
