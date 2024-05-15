package uk.gov.di.ipv.core.checkcoi;

import com.amazonaws.services.lambda.runtime.Context;
import com.amazonaws.services.lambda.runtime.RequestHandler;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import software.amazon.lambda.powertools.logging.Logging;
import software.amazon.lambda.powertools.tracing.Tracing;
import uk.gov.di.ipv.core.library.annotations.ExcludeFromGeneratedCoverageReport;
import uk.gov.di.ipv.core.library.domain.JourneyErrorResponse;
import uk.gov.di.ipv.core.library.domain.JourneyResponse;
import uk.gov.di.ipv.core.library.domain.ProcessRequest;
import uk.gov.di.ipv.core.library.exceptions.CredentialParseException;
import uk.gov.di.ipv.core.library.exceptions.HttpResponseExceptionWithErrorBody;
import uk.gov.di.ipv.core.library.exceptions.VerifiableCredentialException;
import uk.gov.di.ipv.core.library.helpers.LogHelper;
import uk.gov.di.ipv.core.library.helpers.RequestHelper;
import uk.gov.di.ipv.core.library.service.ClientOAuthSessionDetailsService;
import uk.gov.di.ipv.core.library.service.ConfigService;
import uk.gov.di.ipv.core.library.service.IpvSessionService;
import uk.gov.di.ipv.core.library.service.UserIdentityService;
import uk.gov.di.ipv.core.library.verifiablecredential.service.SessionCredentialsService;
import uk.gov.di.ipv.core.library.verifiablecredential.service.VerifiableCredentialService;

import java.util.Map;
import java.util.stream.Stream;

import static org.apache.http.HttpStatus.SC_INTERNAL_SERVER_ERROR;
import static uk.gov.di.ipv.core.library.domain.ErrorResponse.FAILED_TO_PARSE_ISSUED_CREDENTIALS;
import static uk.gov.di.ipv.core.library.helpers.LogHelper.LogField.LOG_COI_SUBJOURNEY_TYPE;
import static uk.gov.di.ipv.core.library.journeyuris.JourneyUris.JOURNEY_COI_CHECK_FAILED_PATH;
import static uk.gov.di.ipv.core.library.journeyuris.JourneyUris.JOURNEY_COI_CHECK_PASSED_PATH;
import static uk.gov.di.ipv.core.library.journeyuris.JourneyUris.JOURNEY_ERROR_PATH;

public class CheckCoiHandler implements RequestHandler<ProcessRequest, Map<String, Object>> {
    private static final Logger LOGGER = LogManager.getLogger();
    private static final JourneyResponse JOURNEY_COI_CHECK_PASSED =
            new JourneyResponse(JOURNEY_COI_CHECK_PASSED_PATH);
    private static final JourneyResponse JOURNEY_COI_CHECK_FAILED =
            new JourneyResponse(JOURNEY_COI_CHECK_FAILED_PATH);

    private final ConfigService configService;
    private final IpvSessionService ipvSessionService;
    private final ClientOAuthSessionDetailsService clientOAuthSessionDetailsService;
    private final VerifiableCredentialService verifiableCredentialService;
    private final SessionCredentialsService sessionCredentialsService;
    private final UserIdentityService userIdentityService;

    public CheckCoiHandler(
            ConfigService configService,
            IpvSessionService ipvSessionService,
            ClientOAuthSessionDetailsService clientOAuthSessionDetailsService,
            VerifiableCredentialService verifiableCredentialService,
            SessionCredentialsService sessionCredentialsService,
            UserIdentityService userIdentityService) {
        this.configService = configService;
        this.ipvSessionService = ipvSessionService;
        this.clientOAuthSessionDetailsService = clientOAuthSessionDetailsService;
        this.verifiableCredentialService = verifiableCredentialService;
        this.sessionCredentialsService = sessionCredentialsService;
        this.userIdentityService = userIdentityService;
    }

    @ExcludeFromGeneratedCoverageReport
    public CheckCoiHandler() {
        this.configService = new ConfigService();
        this.ipvSessionService = new IpvSessionService(configService);
        this.clientOAuthSessionDetailsService = new ClientOAuthSessionDetailsService(configService);
        this.verifiableCredentialService = new VerifiableCredentialService(configService);
        this.sessionCredentialsService = new SessionCredentialsService(configService);
        this.userIdentityService = new UserIdentityService(configService);
    }

    @Override
    @Tracing
    @Logging(clearState = true)
    public Map<String, Object> handleRequest(ProcessRequest request, Context context) {
        configService.setFeatureSet(RequestHelper.getFeatureSet(request));
        LogHelper.attachComponentId(configService);

        try {
            var ipvSession =
                    ipvSessionService.getIpvSession(RequestHelper.getIpvSessionId(request));
            var clientOAuthSession =
                    clientOAuthSessionDetailsService.getClientOAuthSession(
                            ipvSession.getClientOAuthSessionId());
            LogHelper.attachGovukSigninJourneyIdToLogs(
                    clientOAuthSession.getGovukSigninJourneyId());

            var userId = clientOAuthSession.getUserId();

            var credentials =
                    Stream.concat(
                                    verifiableCredentialService.getVcs(userId).stream(),
                                    sessionCredentialsService
                                            .getCredentials(ipvSession.getIpvSessionId(), userId)
                                            .stream())
                            .toList();

            var coiSubjourneyType = ipvSession.getCoiSubjourneyType();
            var successfulCheck =
                    switch (coiSubjourneyType) {
                        case GIVEN_NAMES_ONLY, GIVEN_NAMES_AND_ADDRESS -> userIdentityService
                                .areFamilyNameAndDobCorrelatedForCoiCheck(credentials);
                        case FAMILY_NAME_ONLY, FAMILY_NAME_AND_ADDRESS -> userIdentityService
                                .areGivenNamesAndDobCorrelated(credentials);
                        case ADDRESS_ONLY -> userIdentityService.areVcsCorrelated(credentials);
                    };

            if (!successfulCheck) {
                LOGGER.info(
                        LogHelper.buildLogMessage("Failed COI check")
                                .with(LOG_COI_SUBJOURNEY_TYPE.getFieldName(), coiSubjourneyType));
                return JOURNEY_COI_CHECK_FAILED.toObjectMap();
            }

            LOGGER.info(
                    LogHelper.buildLogMessage("Successful COI check")
                            .with(LOG_COI_SUBJOURNEY_TYPE.getFieldName(), coiSubjourneyType));

            return JOURNEY_COI_CHECK_PASSED.toObjectMap();

        } catch (HttpResponseExceptionWithErrorBody | VerifiableCredentialException e) {
            LOGGER.error(LogHelper.buildErrorMessage("Received exception", e));
            return new JourneyErrorResponse(
                            JOURNEY_ERROR_PATH, e.getResponseCode(), e.getErrorResponse())
                    .toObjectMap();
        } catch (CredentialParseException e) {
            LOGGER.error(LogHelper.buildErrorMessage("Unable to parse existing credentials", e));
            return new JourneyErrorResponse(
                            JOURNEY_ERROR_PATH,
                            SC_INTERNAL_SERVER_ERROR,
                            FAILED_TO_PARSE_ISSUED_CREDENTIALS)
                    .toObjectMap();
        }
    }
}
