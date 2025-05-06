package uk.gov.di.ipv.core.library.evcs.service;

import com.nimbusds.jose.JOSEException;
import com.nimbusds.jwt.JWTClaimsSet;
import uk.gov.di.ipv.core.library.domain.VerifiableCredential;
import uk.gov.di.ipv.core.library.evcs.dto.EvcsStoredIdentityDto;
import uk.gov.di.ipv.core.library.evcs.exception.FailedToCreateStoredIdentityForEvcsException;
import uk.gov.di.ipv.core.library.exceptions.CredentialParseException;
import uk.gov.di.ipv.core.library.exceptions.HttpResponseExceptionWithErrorBody;
import uk.gov.di.ipv.core.library.persistence.item.ClientOAuthSessionItem;
import uk.gov.di.ipv.core.library.service.ConfigService;
import uk.gov.di.ipv.core.library.signing.SignerFactory;
import uk.gov.di.ipv.core.library.useridentity.service.UserIdentityService;
import uk.gov.di.ipv.core.library.useridentity.service.VotMatchingResult;

import java.time.Instant;
import java.util.Date;
import java.util.List;

import static uk.gov.di.ipv.core.library.config.ConfigurationVariable.COMPONENT_ID;
import static uk.gov.di.ipv.core.library.config.ConfigurationVariable.STORED_IDENTITY_SERVICE_COMPONENT_ID;
import static uk.gov.di.ipv.core.library.helpers.JwtHelper.createSignedJwt;

public class StoredIdentityService {
    private final SignerFactory signerFactory;
    private final ConfigService configService;
    private final UserIdentityService userIdentityService;

    public StoredIdentityService(
            SignerFactory signerFactory,
            ConfigService configService,
            UserIdentityService userIdentityService) {
        this.signerFactory = signerFactory;
        this.configService = configService;
        this.userIdentityService = userIdentityService;
    }

    public StoredIdentityService(ConfigService configService) {
        this.signerFactory = new SignerFactory(configService);
        this.userIdentityService = new UserIdentityService(configService);
        this.configService = configService;
    }

    private JWTClaimsSet createStoredIdentityJwt(
            ClientOAuthSessionItem clientOAuthSessionItem,
            List<VerifiableCredential> vcs,
            VotMatchingResult votMatchingResult)
            throws HttpResponseExceptionWithErrorBody, CredentialParseException,
                    FailedToCreateStoredIdentityForEvcsException {
        Instant now = Instant.now();

        var strongestRequestedVot = votMatchingResult.strongestRequestedMatch();
        if (strongestRequestedVot.isEmpty()) {
            throw new FailedToCreateStoredIdentityForEvcsException(
                    "No strongest requested matched vot found for user");
        }

        var claims =
                userIdentityService.getUserClaimsForStoredIdentity(
                        strongestRequestedVot.get().vot(), vcs);

        return new JWTClaimsSet.Builder()
                .issuer(configService.getParameter(COMPONENT_ID))
                .audience(configService.getParameter(STORED_IDENTITY_SERVICE_COMPONENT_ID))
                .subject(clientOAuthSessionItem.getUserId())
                .notBeforeTime(Date.from(now))
                .issueTime(Date.from(now))
                .claim("vot", strongestRequestedVot.get().vot())
                .claim("credentials", vcs.stream().map(VerifiableCredential::getVcString).toList())
                .claim("claims", claims)
                .build();
    }

    private String getSignedStoredIdentity(
            ClientOAuthSessionItem clientOAuthSessionItem,
            List<VerifiableCredential> vcs,
            VotMatchingResult votMatchingResult)
            throws FailedToCreateStoredIdentityForEvcsException {
        try {
            var storedIdentity =
                    createStoredIdentityJwt(clientOAuthSessionItem, vcs, votMatchingResult);

            return createSignedJwt(storedIdentity, signerFactory.getSigner(), false).serialize();
        } catch (CredentialParseException e) {
            throw new FailedToCreateStoredIdentityForEvcsException(
                    "Unable to parse user credentials");
        } catch (HttpResponseExceptionWithErrorBody e) {
            throw new FailedToCreateStoredIdentityForEvcsException(
                    e.getErrorResponse().getMessage());
        } catch (JOSEException e) {
            throw new FailedToCreateStoredIdentityForEvcsException("Failed to create signed JWT");
        }
    }

    public EvcsStoredIdentityDto getStoredIdentityForEvcs(
            ClientOAuthSessionItem clientOAuthSessionItem,
            List<VerifiableCredential> vcs,
            VotMatchingResult votMatchingResult,
            Object metadata)
            throws FailedToCreateStoredIdentityForEvcsException {
        var strongestMatchedVot = votMatchingResult.strongestMatch();
        if (strongestMatchedVot.isEmpty()) {
            throw new FailedToCreateStoredIdentityForEvcsException(
                    "No strongest matched vot found for user");
        }

        var signedSiJwt = getSignedStoredIdentity(clientOAuthSessionItem, vcs, votMatchingResult);

        return new EvcsStoredIdentityDto(signedSiJwt, strongestMatchedVot.get().vot(), metadata);
    }
}
