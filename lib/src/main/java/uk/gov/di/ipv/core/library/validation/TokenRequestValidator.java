package uk.gov.di.ipv.core.library.validation;

import com.nimbusds.jose.JOSEException;
import com.nimbusds.oauth2.sdk.ParseException;
import com.nimbusds.oauth2.sdk.auth.JWTAuthenticationClaimsSet;
import com.nimbusds.oauth2.sdk.auth.PrivateKeyJWT;
import com.nimbusds.oauth2.sdk.auth.verifier.ClientAuthenticationVerifier;
import com.nimbusds.oauth2.sdk.auth.verifier.InvalidClientException;
import com.nimbusds.oauth2.sdk.id.Audience;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import uk.gov.di.ipv.core.library.domain.ConfigurationServicePublicKeySelector;
import uk.gov.di.ipv.core.library.exceptions.ClientAuthenticationException;
import uk.gov.di.ipv.core.library.service.ConfigurationService;

import java.time.OffsetDateTime;
import java.util.Date;
import java.util.Map;
import java.util.Set;

public class TokenRequestValidator {

    private static final Logger LOGGER = LoggerFactory.getLogger(TokenRequestValidator.class);
    private static final String CLIENT_ASSERTION_PARAM = "client_assertion";
    private static final String CLIENT_ID_PARAM = "client_id";
    private static final String NONE = "none";
    private static final String JWT = "jwt";

    private final ConfigurationService configurationService;

    private final ClientAuthenticationVerifier<Object> verifier;

    private String clientId;

    public TokenRequestValidator(ConfigurationService configurationService) {
        this.configurationService = configurationService;
        this.verifier = getClientAuthVerifier(configurationService);
    }

    public void authenticateClient(String requestBody, Map<String, String> queryParams)
            throws ClientAuthenticationException {
        if (!queryParams.containsKey(CLIENT_ASSERTION_PARAM)) {
            authenticateClientWithoutJwt(queryParams);
        } else {
            authenticateClientWithJwt(requestBody);
        }
    }

    private void authenticateClientWithoutJwt(Map<String, String> queryParams)
            throws ClientAuthenticationException {
        if (!queryParams.containsKey(CLIENT_ID_PARAM)) {
            LOGGER.error(
                    "Missing either client_assertion or client_id values in request. Failed to establish client_id value.");
            throw new ClientAuthenticationException(
                    "Unknown client, no client_id value or client_assertion jwt found in request");
        } else {
            clientId = queryParams.get(CLIENT_ID_PARAM);

            String clientAuthenticationMethod =
                    configurationService.getClientAuthenticationMethod(clientId);

            if (clientAuthenticationMethod.equals(JWT)) {
                LOGGER.error("Missing client_assertion jwt for configured client {}", clientId);
                throw new ClientAuthenticationException(
                        String.format(
                                "Missing client_assertion jwt for configured client '%s'",
                                clientId));
            }
        }
    }

    private void authenticateClientWithJwt(String requestBody)
            throws ClientAuthenticationException {
        PrivateKeyJWT clientJwt;
        try {
            clientJwt = PrivateKeyJWT.parse(requestBody);

            clientId = clientJwt.getClientID().getValue();

            String clientAuthenticationMethod =
                    configurationService.getClientAuthenticationMethod(clientId);

            if (clientAuthenticationMethod.equals(NONE)) {
                return;
            }

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
        String maxAllowedTtl = configurationService.getClientTokenTtl(clientId);

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

        ConfigurationServicePublicKeySelector configurationServicePublicKeySelector =
                new ConfigurationServicePublicKeySelector(configurationService);
        return new ClientAuthenticationVerifier<>(
                configurationServicePublicKeySelector,
                Set.of(new Audience(configurationService.getAudienceForClients())));
    }
}
