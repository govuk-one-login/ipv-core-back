package uk.gov.di.ipv.core.library.evcs.service;

import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.nimbusds.jose.JOSEException;
import com.nimbusds.jwt.JWTClaimsSet;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import uk.gov.di.ipv.core.library.domain.VerifiableCredential;
import uk.gov.di.ipv.core.library.enums.Vot;
import uk.gov.di.ipv.core.library.evcs.dto.EvcsStoredIdentityDto;
import uk.gov.di.ipv.core.library.evcs.exception.FailedToCreateStoredIdentityForEvcsException;
import uk.gov.di.ipv.core.library.exceptions.CredentialParseException;
import uk.gov.di.ipv.core.library.exceptions.HttpResponseExceptionWithErrorBody;
import uk.gov.di.ipv.core.library.helpers.LogHelper;
import uk.gov.di.ipv.core.library.service.ConfigService;
import uk.gov.di.ipv.core.library.signing.SignerFactory;
import uk.gov.di.ipv.core.library.useridentity.service.UserIdentityService;
import uk.gov.di.ipv.core.library.useridentity.service.VotMatchingResult;

import java.time.Clock;
import java.time.Instant;
import java.util.Date;
import java.util.List;
import java.util.Objects;

import static uk.gov.di.ipv.core.library.config.ConfigurationVariable.COMPONENT_ID;
import static uk.gov.di.ipv.core.library.config.ConfigurationVariable.STORED_IDENTITY_SERVICE_COMPONENT_ID;
import static uk.gov.di.ipv.core.library.helpers.JwtHelper.createSignedJwt;

public class StoredIdentityService {
    public static final String VOT_CLAIM = "vot";
    public static final String CREDENTIALS_CLAIM = "credentials";
    public static final String CLAIMS_CLAIM = "claims";

    private static final Logger LOGGER = LogManager.getLogger();
    private static final ObjectMapper OBJECT_MAPPER = new ObjectMapper();
    private final SignerFactory signerFactory;
    private final ConfigService configService;
    private final UserIdentityService userIdentityService;
    private final Clock clock;

    public StoredIdentityService(
            ConfigService configService,
            SignerFactory signerFactory,
            UserIdentityService userIdentityService,
            Clock clock) {
        this.signerFactory = signerFactory;
        this.configService = configService;
        this.userIdentityService = userIdentityService;
        this.clock = clock;
    }

    public StoredIdentityService(ConfigService configService) {
        this.signerFactory = new SignerFactory(configService);
        this.userIdentityService = new UserIdentityService(configService);
        this.configService = configService;
        this.clock = Clock.systemDefaultZone();
    }

    private JWTClaimsSet createStoredIdentityJwt(
            String userId, List<VerifiableCredential> vcs, Vot achievedVot)
            throws HttpResponseExceptionWithErrorBody, CredentialParseException {
        Instant now = Instant.now(clock);

        // the serialiseNullClaims(false) on JWTClaimsSet.Builder doesn't work to
        // remove null properties within the claims value (only if the claims value
        // is null itself) so we do this prior to passing it into JWTClaimsSet.Builder
        // with jackson.
        var parsedUserClaims =
                OBJECT_MAPPER.convertValue(
                        userIdentityService.getUserClaimsForStoredIdentity(achievedVot, vcs),
                        new TypeReference<>() {});

        return new JWTClaimsSet.Builder()
                .issuer(configService.getParameter(COMPONENT_ID))
                .audience(configService.getParameter(STORED_IDENTITY_SERVICE_COMPONENT_ID))
                .subject(userId)
                .notBeforeTime(Date.from(now))
                .issueTime(Date.from(now))
                .claim(VOT_CLAIM, achievedVot)
                .claim(
                        CREDENTIALS_CLAIM,
                        vcs.stream()
                                .map(vc -> vc.getSignedJwt().getSignature().toString())
                                .toList())
                .claim(CLAIMS_CLAIM, parsedUserClaims)
                .build();
    }

    private String getSignedStoredIdentityForEvcs(
            String userId, List<VerifiableCredential> vcs, Vot achievedVot)
            throws FailedToCreateStoredIdentityForEvcsException {
        try {
            var storedIdentity = createStoredIdentityJwt(userId, vcs, achievedVot);

            return createSignedJwt(storedIdentity, signerFactory.getSigner()).serialize();
        } catch (CredentialParseException e) {
            LOGGER.error(LogHelper.buildLogMessage("Unable to parse user credentials"));
            throw new FailedToCreateStoredIdentityForEvcsException(
                    "Unable to parse user credentials");
        } catch (HttpResponseExceptionWithErrorBody e) {
            LOGGER.error(LogHelper.buildLogMessage(e.getErrorResponse().getMessage()));
            throw new FailedToCreateStoredIdentityForEvcsException(
                    e.getErrorResponse().getMessage());
        } catch (JOSEException e) {
            LOGGER.error(LogHelper.buildLogMessage("Failed to create signed JWT"));
            throw new FailedToCreateStoredIdentityForEvcsException("Failed to create signed JWT");
        }
    }

    public EvcsStoredIdentityDto getStoredIdentityForEvcs(
            String userId,
            List<VerifiableCredential> vcs,
            VotMatchingResult.VotAndProfile strongestMatchedVot,
            Vot achievedVot)
            throws FailedToCreateStoredIdentityForEvcsException {
        if (Objects.isNull(strongestMatchedVot)) {
            LOGGER.error(LogHelper.buildLogMessage("No strongest matched vot found for user"));
            throw new FailedToCreateStoredIdentityForEvcsException(
                    "No strongest matched vot found for user");
        }

        var signedSiJwt = getSignedStoredIdentityForEvcs(userId, vcs, achievedVot);

        return new EvcsStoredIdentityDto(signedSiJwt, strongestMatchedVot.vot());
    }
}
