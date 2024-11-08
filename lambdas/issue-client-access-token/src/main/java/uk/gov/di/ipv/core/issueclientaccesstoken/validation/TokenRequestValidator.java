package uk.gov.di.ipv.core.issueclientaccesstoken.validation;

import com.nimbusds.jose.JOSEException;
import com.nimbusds.oauth2.sdk.ParseException;
import com.nimbusds.oauth2.sdk.auth.JWTAuthenticationClaimsSet;
import com.nimbusds.oauth2.sdk.auth.PrivateKeyJWT;
import com.nimbusds.oauth2.sdk.auth.verifier.ClientAuthenticationVerifier;
import com.nimbusds.oauth2.sdk.auth.verifier.InvalidClientException;
import com.nimbusds.oauth2.sdk.id.Audience;
import com.nimbusds.oauth2.sdk.id.JWTID;
import com.nimbusds.oauth2.sdk.util.StringUtils;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import software.amazon.lambda.powertools.logging.LoggingUtils;
import uk.gov.di.ipv.core.issueclientaccesstoken.domain.ConfigurationServicePublicKeySelector;
import uk.gov.di.ipv.core.issueclientaccesstoken.exception.ClientAuthenticationException;
import uk.gov.di.ipv.core.issueclientaccesstoken.persistance.item.ClientAuthJwtIdItem;
import uk.gov.di.ipv.core.issueclientaccesstoken.service.ClientAuthJwtIdService;
import uk.gov.di.ipv.core.library.helpers.LogHelper;
import uk.gov.di.ipv.core.library.oauthkeyservice.OAuthKeyService;
import uk.gov.di.ipv.core.library.service.ConfigService;

import java.time.OffsetDateTime;
import java.util.Date;
import java.util.Set;

import static uk.gov.di.ipv.core.library.config.ConfigurationVariable.COMPONENT_ID;
import static uk.gov.di.ipv.core.library.config.ConfigurationVariable.MAX_ALLOWED_AUTH_CLIENT_TTL;

public class TokenRequestValidator {
    private static final Logger LOGGER = LogManager.getLogger();

    private final ConfigService configService;
    private final ClientAuthJwtIdService clientAuthJwtIdService;
    private final OAuthKeyService oAuthKeyService;

    private ClientAuthenticationVerifier<Object> clientAuthVerifier;

    public TokenRequestValidator(
            ConfigService configService,
            ClientAuthJwtIdService clientAuthJwtIdService,
            OAuthKeyService oAuthKeyService) {
        this.configService = configService;
        this.clientAuthJwtIdService = clientAuthJwtIdService;
        this.oAuthKeyService = oAuthKeyService;
    }

    public void authenticateClient(String requestBody) throws ClientAuthenticationException {
        if (clientAuthVerifier == null) {
            this.clientAuthVerifier = getClientAuthVerifier(configService);
        }
        PrivateKeyJWT clientJwt;
        try {
            clientJwt = PrivateKeyJWT.parse(requestBody);
            LogHelper.attachClientIdToLogs(clientJwt.getClientID().getValue());
            clientAuthVerifier.verify(clientJwt, null, null);
            JWTAuthenticationClaimsSet claimsSet = clientJwt.getJWTAuthenticationClaimsSet();
            validateMaxAllowedAuthClientTtl(claimsSet);
            validateJwtId(claimsSet);
        } catch (ParseException | InvalidClientException | JOSEException e) {
            LOGGER.error(LogHelper.buildLogMessage("Validation of client_assertion jwt failed"));
            throw new ClientAuthenticationException(e);
        }
    }

    private void validateMaxAllowedAuthClientTtl(JWTAuthenticationClaimsSet claimsSet)
            throws InvalidClientException {
        Date expirationTime = claimsSet.getExpirationTime();
        long maxAllowedTtlSeconds = configService.getLongParameter(MAX_ALLOWED_AUTH_CLIENT_TTL);

        OffsetDateTime offsetDateTime = OffsetDateTime.now().plusSeconds(maxAllowedTtlSeconds);
        if (expirationTime.getTime() / 1000L > offsetDateTime.toEpochSecond()) {
            LOGGER.error(
                    LogHelper.buildLogMessage("Client JWT expiry date is too far in the future"));
            throw new InvalidClientException(
                    "The client JWT expiry date has surpassed the maximum allowed ttl value");
        }
    }

    private void validateJwtId(JWTAuthenticationClaimsSet claimsSet) throws InvalidClientException {
        JWTID jwtId = claimsSet.getJWTID();
        if (jwtId == null || StringUtils.isBlank(jwtId.getValue())) {
            LOGGER.error(LogHelper.buildLogMessage("The client auth JWT id (jti) is missing."));
            throw new InvalidClientException("The client auth JWT id (jti) is missing.");
        }
        ClientAuthJwtIdItem clientAuthJwtIdItem =
                clientAuthJwtIdService.getClientAuthJwtIdItem(jwtId.getValue());
        if (clientAuthJwtIdItem != null) {
            logErrorJtiHasAlreadyBeenUsed(clientAuthJwtIdItem);
            throw new InvalidClientException("The client auth JWT id (jti) has already been used.");
        }
        clientAuthJwtIdService.persistClientAuthJwtId(jwtId.getValue());
    }

    private ClientAuthenticationVerifier<Object> getClientAuthVerifier(
            ConfigService configService) {

        return new ClientAuthenticationVerifier<>(
                new ConfigurationServicePublicKeySelector(oAuthKeyService),
                Set.of(new Audience(configService.getParameter(COMPONENT_ID))));
    }

    private void logErrorJtiHasAlreadyBeenUsed(ClientAuthJwtIdItem clientAuthJwtIdItem) {
        LoggingUtils.appendKey(
                LogHelper.LogField.LOG_JTI.getFieldName(), clientAuthJwtIdItem.getJwtId());
        LoggingUtils.appendKey(
                LogHelper.LogField.LOG_JTI_USED_AT.getFieldName(),
                clientAuthJwtIdItem.getUsedAtDateTime());
        LOGGER.error(
                LogHelper.buildLogMessage("The client auth JWT id (jti) has already been used"));
        LoggingUtils.removeKeys(
                LogHelper.LogField.LOG_JTI.getFieldName(),
                LogHelper.LogField.LOG_JTI_USED_AT.getFieldName());
    }
}
