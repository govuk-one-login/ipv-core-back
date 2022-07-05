package uk.gov.di.ipv.core.library.validation;

import com.nimbusds.jose.JOSEException;
import com.nimbusds.oauth2.sdk.ParseException;
import com.nimbusds.oauth2.sdk.auth.JWTAuthenticationClaimsSet;
import com.nimbusds.oauth2.sdk.auth.PrivateKeyJWT;
import com.nimbusds.oauth2.sdk.auth.verifier.ClientAuthenticationVerifier;
import com.nimbusds.oauth2.sdk.auth.verifier.InvalidClientException;
import com.nimbusds.oauth2.sdk.id.Audience;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import uk.gov.di.ipv.core.library.domain.ConfigurationServicePublicKeySelector;
import uk.gov.di.ipv.core.library.exceptions.ClientAuthenticationException;
import uk.gov.di.ipv.core.library.helpers.LogHelper;
import uk.gov.di.ipv.core.library.service.ConfigurationService;

import java.time.OffsetDateTime;
import java.util.Date;
import java.util.Set;

import static uk.gov.di.ipv.core.library.config.ConfigurationVariable.AUDIENCE_FOR_CLIENTS;
import static uk.gov.di.ipv.core.library.config.ConfigurationVariable.MAX_ALLOWED_AUTH_CLIENT_TTL;

public class TokenRequestValidator {

    private static final Logger LOGGER = LogManager.getLogger();
    private final ConfigurationService configurationService;
    private final ClientAuthenticationVerifier<Object> verifier;

    public TokenRequestValidator(ConfigurationService configurationService) {
        this.configurationService = configurationService;
        this.verifier = getClientAuthVerifier(configurationService);
    }

    public void authenticateClient(String requestBody) throws ClientAuthenticationException {
        PrivateKeyJWT clientJwt;
        try {
            clientJwt = PrivateKeyJWT.parse(requestBody);
            LogHelper.attachClientIdToLogs(clientJwt.getClientID().getValue());
            verifier.verify(clientJwt, null, null);
            validateMaxAllowedAuthClientTtl(clientJwt.getJWTAuthenticationClaimsSet());
        } catch (ParseException | InvalidClientException | JOSEException e) {
            LOGGER.error("Validation of client_assertion jwt failed");
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
            LOGGER.error("Client JWT expiry date is too far in the future");
            throw new InvalidClientException(
                    "The client JWT expiry date has surpassed the maximum allowed ttl value");
        }
    }

    private ClientAuthenticationVerifier<Object> getClientAuthVerifier(
            ConfigurationService configurationService) {

        return new ClientAuthenticationVerifier<>(
                new ConfigurationServicePublicKeySelector(configurationService),
                Set.of(new Audience(configurationService.getSsmParameter(AUDIENCE_FOR_CLIENTS))));
    }
}
