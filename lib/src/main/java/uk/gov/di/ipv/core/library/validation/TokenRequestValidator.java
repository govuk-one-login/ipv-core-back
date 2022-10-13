package uk.gov.di.ipv.core.library.validation;

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
import org.apache.logging.log4j.message.MapMessage;
import org.apache.logging.log4j.message.StringMapMessage;
import uk.gov.di.ipv.core.library.domain.ConfigurationServicePublicKeySelector;
import uk.gov.di.ipv.core.library.exceptions.ClientAuthenticationException;
import uk.gov.di.ipv.core.library.helpers.LogHelper;
import uk.gov.di.ipv.core.library.persistence.item.ClientAuthJwtIdItem;
import uk.gov.di.ipv.core.library.service.ClientAuthJwtIdService;
import uk.gov.di.ipv.core.library.service.ConfigurationService;

import java.time.OffsetDateTime;
import java.util.Date;
import java.util.Set;

import static uk.gov.di.ipv.core.library.config.ConfigurationVariable.AUDIENCE_FOR_CLIENTS;
import static uk.gov.di.ipv.core.library.config.ConfigurationVariable.MAX_ALLOWED_AUTH_CLIENT_TTL;

public class TokenRequestValidator {

    private static final Logger LOGGER = LogManager.getLogger();
    private final ConfigurationService configurationService;

    private final ClientAuthJwtIdService clientAuthJwtIdService;
    private final ClientAuthenticationVerifier<Object> verifier;

    public TokenRequestValidator(
            ConfigurationService configurationService,
            ClientAuthJwtIdService clientAuthJwtIdService) {
        this.configurationService = configurationService;
        this.clientAuthJwtIdService = clientAuthJwtIdService;
        this.verifier = getClientAuthVerifier(configurationService);
    }

    public void authenticateClient(String requestBody) throws ClientAuthenticationException {
        PrivateKeyJWT clientJwt;
        try {
            clientJwt = PrivateKeyJWT.parse(requestBody);
            LogHelper.attachClientIdToLogs(clientJwt.getClientID().getValue());
            verifier.verify(clientJwt, null, null);
            JWTAuthenticationClaimsSet claimsSet = clientJwt.getJWTAuthenticationClaimsSet();
            validateMaxAllowedAuthClientTtl(claimsSet);
            validateJwtId(claimsSet);
        } catch (ParseException | InvalidClientException | JOSEException e) {
            var message =
                    new MapMessage()
                            .with("jwtValidation", "Validation of client_assertion jwt failed");
            LOGGER.error(message);
            throw new ClientAuthenticationException(e);
        }
    }

    private void validateMaxAllowedAuthClientTtl(JWTAuthenticationClaimsSet claimsSet)
            throws InvalidClientException {
        Date expirationTime = claimsSet.getExpirationTime();
        String maxAllowedTtl = configurationService.getSsmParameter(MAX_ALLOWED_AUTH_CLIENT_TTL);

        OffsetDateTime offsetDateTime =
                OffsetDateTime.now().plusSeconds(Long.parseLong(maxAllowedTtl));
        if (expirationTime.getTime() / 1000L > offsetDateTime.toEpochSecond()) {
            var message =
                    new MapMessage()
                            .with(
                                    "jwtValidation",
                                    "Client JWT expiry date is too far in the future")
                            .with("exp", expirationTime.getTime());
            LOGGER.warn(message);
            throw new InvalidClientException(
                    "The client JWT expiry date has surpassed the maximum allowed ttl value");
        }
    }

    private void validateJwtId(JWTAuthenticationClaimsSet claimsSet) {
        JWTID jwtId = claimsSet.getJWTID();
        if (jwtId == null || StringUtils.isBlank(jwtId.getValue())) {
            var message =
                    new MapMessage()
                            .with("jwtValidation", "The client auth JWT id (jti) is missing");
            LOGGER.warn(message);
            return;
        }
        ClientAuthJwtIdItem clientAuthJwtIdItem =
                clientAuthJwtIdService.getClientAuthJwtIdItem(jwtId.getValue());
        if (clientAuthJwtIdItem != null) {
            logWarningJtiHasAlreadyBeenUsed(clientAuthJwtIdItem);
        }
        clientAuthJwtIdService.persistClientAuthJwtId(jwtId.getValue());
    }

    private ClientAuthenticationVerifier<Object> getClientAuthVerifier(
            ConfigurationService configurationService) {

        return new ClientAuthenticationVerifier<>(
                new ConfigurationServicePublicKeySelector(configurationService),
                Set.of(new Audience(configurationService.getSsmParameter(AUDIENCE_FOR_CLIENTS))));
    }

    private void logWarningJtiHasAlreadyBeenUsed(ClientAuthJwtIdItem clientAuthJwtIdItem) {
        var message =
                new StringMapMessage()
                        .with("jwtValidation", "The client auth JWT id (jti) has already been used")
                        .with("jti", clientAuthJwtIdItem.getJwtId())
                        .with("used", clientAuthJwtIdItem.getUsedAtDateTime());
        LOGGER.warn(message);
    }
}
