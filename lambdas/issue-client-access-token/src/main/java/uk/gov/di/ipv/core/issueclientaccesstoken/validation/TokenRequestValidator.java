package uk.gov.di.ipv.core.issueclientaccesstoken.validation;

import com.nimbusds.jose.JOSEException;
import com.nimbusds.oauth2.sdk.ParseException;
import com.nimbusds.oauth2.sdk.auth.JWTAuthenticationClaimsSet;
import com.nimbusds.oauth2.sdk.auth.PrivateKeyJWT;
import com.nimbusds.oauth2.sdk.auth.verifier.ClientAuthenticationVerifier;
import com.nimbusds.oauth2.sdk.auth.verifier.InvalidClientException;
import com.nimbusds.oauth2.sdk.auth.verifier.JWTAudienceCheck;
import com.nimbusds.oauth2.sdk.id.Audience;
import com.nimbusds.oauth2.sdk.util.StringUtils;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import uk.gov.di.ipv.core.issueclientaccesstoken.domain.OAuthKeyServiceClientCredentialsSelector;
import uk.gov.di.ipv.core.issueclientaccesstoken.exception.ClientAuthenticationException;
import uk.gov.di.ipv.core.issueclientaccesstoken.service.ClientAuthJwtIdService;
import uk.gov.di.ipv.core.library.helpers.LogHelper;
import uk.gov.di.ipv.core.library.oauthkeyservice.OAuthKeyService;
import uk.gov.di.ipv.core.library.service.ConfigService;

import java.time.Instant;
import java.util.Set;

import static uk.gov.di.ipv.core.library.helpers.LogHelper.LogField.LOG_JTI;
import static uk.gov.di.ipv.core.library.helpers.LogHelper.LogField.LOG_JTI_USED_AT;

public class TokenRequestValidator {
    private static final Logger LOGGER = LogManager.getLogger();

    private final ConfigService configService;
    private final ClientAuthJwtIdService clientAuthJwtIdService;
    private final OAuthKeyService oAuthKeyService;

    public TokenRequestValidator(
            ConfigService configService,
            ClientAuthJwtIdService clientAuthJwtIdService,
            OAuthKeyService oAuthKeyService) {
        this.configService = configService;
        this.clientAuthJwtIdService = clientAuthJwtIdService;
        this.oAuthKeyService = oAuthKeyService;
    }

    public void authenticateClient(String requestBody) throws ClientAuthenticationException {
        try {
            var clientJwt = PrivateKeyJWT.parse(requestBody);
            LogHelper.attachClientIdToLogs(clientJwt.getClientID().getValue());

            getClientAuthVerifier(configService).verify(clientJwt, null, null);

            var claimsSet = clientJwt.getJWTAuthenticationClaimsSet();
            validateMaxAllowedAuthClientTtl(claimsSet);
            validateJwtId(claimsSet);
        } catch (ParseException | InvalidClientException | JOSEException e) {
            LOGGER.error(
                    LogHelper.buildErrorMessage("Validation of client_assertion jwt failed", e));
            throw new ClientAuthenticationException(e);
        }
    }

    private void validateMaxAllowedAuthClientTtl(JWTAuthenticationClaimsSet claimsSet)
            throws InvalidClientException {
        var maxAllowedTtlInstant =
                Instant.now().plusSeconds(configService.getMaxAllowedAuthClientTtl());

        if (claimsSet.getExpirationTime().toInstant().isAfter(maxAllowedTtlInstant)) {
            LOGGER.error(
                    LogHelper.buildLogMessage("Client JWT expiry date is too far in the future"));
            throw new InvalidClientException(
                    "The client JWT expiry date has surpassed the maximum allowed ttl value");
        }
    }

    private void validateJwtId(JWTAuthenticationClaimsSet claimsSet) throws InvalidClientException {
        var jwtId = claimsSet.getJWTID();
        if (jwtId == null || StringUtils.isBlank(jwtId.getValue())) {
            LOGGER.error(LogHelper.buildLogMessage("The client auth JWT id (jti) is missing."));
            throw new InvalidClientException("The client auth JWT id (jti) is missing.");
        }
        var clientAuthJwtIdItem = clientAuthJwtIdService.getClientAuthJwtIdItem(jwtId.getValue());
        if (clientAuthJwtIdItem != null) {
            LOGGER.error(
                    LogHelper.buildLogMessage("The client auth JWT id (jti) has already been used")
                            .with(LOG_JTI.getFieldName(), clientAuthJwtIdItem.getJwtId())
                            .with(
                                    LOG_JTI_USED_AT.getFieldName(),
                                    clientAuthJwtIdItem.getUsedAtDateTime()));
            throw new InvalidClientException("The client auth JWT id (jti) has already been used.");
        }
        clientAuthJwtIdService.persistClientAuthJwtId(jwtId.getValue());
    }

    private ClientAuthenticationVerifier<Object> getClientAuthVerifier(
            ConfigService configService) {
        return new ClientAuthenticationVerifier<>(
                new OAuthKeyServiceClientCredentialsSelector(oAuthKeyService),
                Set.of(new Audience(configService.getComponentId())),
                JWTAudienceCheck.STRICT);
    }
}
