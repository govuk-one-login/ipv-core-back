package uk.gov.di.ipv.core.identitycontinuitycheck;

import com.amazonaws.services.lambda.runtime.Context;
import com.amazonaws.services.lambda.runtime.RequestHandler;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import software.amazon.lambda.powertools.logging.Logging;
import software.amazon.lambda.powertools.tracing.Tracing;
import uk.gov.di.ipv.core.library.annotations.ExcludeFromGeneratedCoverageReport;
import uk.gov.di.ipv.core.library.config.ConfigurationVariable;
import uk.gov.di.ipv.core.library.domain.ErrorResponse;
import uk.gov.di.ipv.core.library.domain.IdentityClaim;
import uk.gov.di.ipv.core.library.domain.JourneyErrorResponse;
import uk.gov.di.ipv.core.library.domain.JourneyResponse;
import uk.gov.di.ipv.core.library.domain.ProcessRequest;
import uk.gov.di.ipv.core.library.exceptions.CredentialParseException;
import uk.gov.di.ipv.core.library.exceptions.HttpResponseExceptionWithErrorBody;
import uk.gov.di.ipv.core.library.exceptions.VerifiableCredentialException;
import uk.gov.di.ipv.core.library.helpers.LogHelper;
import uk.gov.di.ipv.core.library.helpers.RequestHelper;
import uk.gov.di.ipv.core.library.persistence.item.ClientOAuthSessionItem;
import uk.gov.di.ipv.core.library.persistence.item.IpvSessionItem;
import uk.gov.di.ipv.core.library.service.ClientOAuthSessionDetailsService;
import uk.gov.di.ipv.core.library.service.ConfigService;
import uk.gov.di.ipv.core.library.service.IpvSessionService;
import uk.gov.di.ipv.core.library.service.UserIdentityService;
import uk.gov.di.ipv.core.library.verifiablecredential.service.SessionCredentialsService;
import uk.gov.di.ipv.core.library.verifiablecredential.service.VerifiableCredentialService;

import java.util.Map;
import java.util.Optional;
import java.util.function.BiPredicate;

import static uk.gov.di.ipv.core.library.journeyuris.JourneyUris.JOURNEY_CONTINUING_IDENTITY_CHECK_PASS_PATH;
import static uk.gov.di.ipv.core.library.journeyuris.JourneyUris.JOURNEY_ERROR_PATH;
import static uk.gov.di.ipv.core.library.service.UserIdentityService.FAMILY_NAME_PROPERTY_NAME;
import static uk.gov.di.ipv.core.library.service.UserIdentityService.GIVEN_NAME_PROPERTY_NAME;

public class IdentityContinuityCheckHandler
        implements RequestHandler<ProcessRequest, Map<String, Object>> {
    private static final Logger LOGGER = LogManager.getLogger();
    private static final Map<String, Object> JOURNEY_CONTINUING_IDENTITY_CHECK_PASS =
            new JourneyResponse(JOURNEY_CONTINUING_IDENTITY_CHECK_PASS_PATH).toObjectMap();
    private final ConfigService configService;
    private final UserIdentityService userIdentityService;
    private final SessionCredentialsService sessionCredentialsService;
    private final IpvSessionService ipvSessionService;
    private final VerifiableCredentialService verifiableCredentialService;
    private final ClientOAuthSessionDetailsService clientOAuthSessionDetailsService;

    public IdentityContinuityCheckHandler(
            ConfigService configService,
            UserIdentityService userIdentityService,
            SessionCredentialsService sessionCredentialsService,
            IpvSessionService ipvSessionService,
            VerifiableCredentialService verifiableCredentialService,
            ClientOAuthSessionDetailsService clientOAuthSessionDetailsService) {
        this.configService = configService;
        this.userIdentityService = userIdentityService;
        this.sessionCredentialsService = sessionCredentialsService;
        this.ipvSessionService = ipvSessionService;
        this.verifiableCredentialService = verifiableCredentialService;
        this.clientOAuthSessionDetailsService = clientOAuthSessionDetailsService;
    }

    @ExcludeFromGeneratedCoverageReport
    public IdentityContinuityCheckHandler(UserIdentityService userIdentityService) {
        this.configService = new ConfigService();
        this.userIdentityService = new UserIdentityService(configService);
        this.ipvSessionService = new IpvSessionService(configService);
        this.clientOAuthSessionDetailsService = new ClientOAuthSessionDetailsService(configService);
        this.sessionCredentialsService = new SessionCredentialsService(configService);
        this.verifiableCredentialService = new VerifiableCredentialService(configService);
    }

    @Override
    @Tracing
    @Logging(clearState = true)
    public Map<String, Object> handleRequest(ProcessRequest input, Context context) {
        LogHelper.attachComponentId(configService);
        configService.setFeatureSet(RequestHelper.getFeatureSet(input));

        try {

            IpvSessionItem ipvSessionItem =
                    ipvSessionService.getIpvSession(RequestHelper.getIpvSessionId(input));
            ClientOAuthSessionItem clientOAuthSessionItem =
                    clientOAuthSessionDetailsService.getClientOAuthSession(
                            ipvSessionItem.getClientOAuthSessionId());
            LogHelper.attachGovukSigninJourneyIdToLogs(
                    clientOAuthSessionItem.getGovukSigninJourneyId());
            var sessionCredentials =
                    sessionCredentialsService.getCredentials(
                            ipvSessionItem.getIpvSessionId(), clientOAuthSessionItem.getUserId());
            var verifiableCredentials =
                    verifiableCredentialService.getVcs(clientOAuthSessionItem.getUserId());
            final Optional<IdentityClaim> sessionCredentialsIdentityClaims =
                    userIdentityService.findIdentityClaim(sessionCredentials);
            final Optional<IdentityClaim> verifiableCredentialsIdentityClaims =
                    userIdentityService.findIdentityClaim(verifiableCredentials);

            if (sessionCredentialsIdentityClaims.isPresent()
                    && verifiableCredentialsIdentityClaims.isPresent()) {
                IdentityClaim sessionCredentialsIdentityClaim =
                        sessionCredentialsIdentityClaims.get();
                IdentityClaim verifiableCredentialsIdentityClaim =
                        verifiableCredentialsIdentityClaims.get();

                if (!sessionCredentialsIdentityClaim
                        .getBirthDate()
                        .equals(verifiableCredentialsIdentityClaim.getBirthDate())) {
                    return new JourneyErrorResponse(
                                    JOURNEY_ERROR_PATH,
                                    ErrorResponse.IDENTITY_CONTINUITY_CHECK_FAILED.getCode(),
                                    ErrorResponse.IDENTITY_CONTINUITY_CHECK_FAILED)
                            .toObjectMap();
                }
                BiPredicate<IdentityClaim, IdentityClaim> continuityCheck;

                var changeType = ipvSessionItem.getCoiSubjourneyType();

                continuityCheck =
                        switch (changeType) {
                            case GIVEN_NAMES_ONLY -> this::isIdentityContinuityMatchFamilyName;
                            case FAMILY_NAME_ONLY -> this::isIdentityContinuityMatchGivenName;
                            case ADDRESS_ONLY -> this::isIdentityContinuityMatchIntervention;
                            default -> throw new IllegalArgumentException(
                                    "Invalid change type: " + changeType);
                        };

                if (!continuityCheck.test(
                        sessionCredentialsIdentityClaim, verifiableCredentialsIdentityClaim)) {
                    return new JourneyErrorResponse(
                                    JOURNEY_ERROR_PATH,
                                    ErrorResponse.IDENTITY_CONTINUITY_CHECK_FAILED.getCode(),
                                    ErrorResponse.IDENTITY_CONTINUITY_CHECK_FAILED)
                            .toObjectMap();
                }

                return JOURNEY_CONTINUING_IDENTITY_CHECK_PASS;
            }

            return new JourneyErrorResponse(
                            JOURNEY_ERROR_PATH,
                            ErrorResponse.FAILED_TO_PARSE_ISSUED_CREDENTIALS.getCode(),
                            ErrorResponse.FAILED_TO_PARSE_ISSUED_CREDENTIALS)
                    .toObjectMap();

        } catch (HttpResponseExceptionWithErrorBody | VerifiableCredentialException e) {
            LOGGER.error(LogHelper.buildErrorMessage("Error fetching identity", e));
            return new JourneyErrorResponse(
                            JOURNEY_ERROR_PATH, e.getResponseCode(), e.getErrorResponse())
                    .toObjectMap();
        } catch (CredentialParseException e) {
            LOGGER.error(LogHelper.buildErrorMessage("Error parsing credential", e));
            return new JourneyErrorResponse(
                            JOURNEY_ERROR_PATH,
                            ErrorResponse.FAILED_TO_PARSE_ISSUED_CREDENTIALS.getCode(),
                            ErrorResponse.FAILED_TO_PARSE_ISSUED_CREDENTIALS)
                    .toObjectMap();
        }
    }
    //    types of changes
    public boolean isIdentityContinuityMatchGivenName(
            IdentityClaim currentIdentity, IdentityClaim newIdentity) {
        int coiIdentityVerificationCount = Integer.parseInt(
                configService.getSsmParameter(
                        ConfigurationVariable.COI_IDENTITY_VERIFICATION_COUNT_GIVEN_NAME));

        String currentGivenName =
                userIdentityService.getNormalizedName(currentIdentity, GIVEN_NAME_PROPERTY_NAME);
        String newGivenName =
                userIdentityService.getNormalizedName(newIdentity, GIVEN_NAME_PROPERTY_NAME);

        int shortestName = Math.min(currentGivenName.length(), newGivenName.length());
        int checkLength = Math.min(shortestName, coiIdentityVerificationCount);

        return currentGivenName.substring(0, checkLength)
                .equals(newGivenName.substring(0, checkLength));
    }

    public boolean isIdentityContinuityMatchFamilyName(
            IdentityClaim currentIdentity, IdentityClaim newIdentity) {
        int coiIdentityVerificationCount = Integer.parseInt(
                configService.getSsmParameter(
                        ConfigurationVariable.COI_IDENTITY_VERIFICATION_COUNT_FAMILY_NAME));

        String currentFamilyName =
                userIdentityService.getNormalizedName(currentIdentity, FAMILY_NAME_PROPERTY_NAME);
        String newFamilyName =
                userIdentityService.getNormalizedName(newIdentity, FAMILY_NAME_PROPERTY_NAME);

        int shortestName = Math.min(currentFamilyName.length(), newFamilyName.length());
        int checkLength = Math.min(shortestName, coiIdentityVerificationCount);

        return currentFamilyName.substring(0, checkLength)
                .equals(newFamilyName.substring(0, checkLength));
    }

    public boolean isIdentityContinuityMatchIntervention(
            IdentityClaim currentIdentity, IdentityClaim newIdentity) {

        return currentIdentity.getFullName().equals(newIdentity.getFullName());
    }
}
