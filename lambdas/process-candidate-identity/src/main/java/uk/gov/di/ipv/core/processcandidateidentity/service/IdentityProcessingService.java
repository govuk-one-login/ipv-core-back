package uk.gov.di.ipv.core.processcandidateidentity.service;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.apache.logging.log4j.message.StringMapMessage;
import uk.gov.di.ipv.core.library.annotations.ExcludeFromGeneratedCoverageReport;
import uk.gov.di.ipv.core.library.cristoringservice.CriStoringService;
import uk.gov.di.ipv.core.library.domain.JourneyResponse;
import uk.gov.di.ipv.core.library.journeys.JourneyUris;
import uk.gov.di.ipv.core.library.service.AuditService;
import uk.gov.di.ipv.core.library.service.CimitService;
import uk.gov.di.ipv.core.library.service.CimitUtilityService;
import uk.gov.di.ipv.core.library.service.ConfigService;
import uk.gov.di.ipv.core.library.service.UserIdentityService;
import uk.gov.di.ipv.core.library.verifiablecredential.service.SessionCredentialsService;

import java.util.List;
import java.util.function.Supplier;

import static uk.gov.di.ipv.core.library.helpers.LogHelper.LogField.LOG_JOURNEY_RESPONSE;
import static uk.gov.di.ipv.core.library.helpers.LogHelper.LogField.LOG_LAMBDA_RESULT;
import static uk.gov.di.ipv.core.library.journeys.JourneyUris.JOURNEY_COI_CHECK_FAILED_PATH;
import static uk.gov.di.ipv.core.library.journeys.JourneyUris.JOURNEY_GPG45_UNMET_PATH;
import static uk.gov.di.ipv.core.library.journeys.JourneyUris.JOURNEY_NEXT_PATH;

public class IdentityProcessingService {
    private static final Logger LOGGER = LogManager.getLogger();

    private static final JourneyResponse JOURNEY_NEXT = new JourneyResponse(JOURNEY_NEXT_PATH);
    private static final JourneyResponse JOURNEY_GPG45_UNMET =
            new JourneyResponse(JOURNEY_GPG45_UNMET_PATH);
    private static final JourneyResponse JOURNEY_VCS_NOT_CORRELATED =
            new JourneyResponse(JourneyUris.JOURNEY_VCS_NOT_CORRELATED);
    private static final JourneyResponse JOURNEY_COI_CHECK_FAILED =
            new JourneyResponse(JOURNEY_COI_CHECK_FAILED_PATH);

    private final TicfCriService ticfCriService;
    private final CriStoringService criStoringService;
    private final AuditService auditService;
    private final CimitService cimitService;
    private final CimitUtilityService cimitUtilityService;
    private final EvaluateGpg45ScoresService evaluateGpg45ScoresService;
    private final SessionCredentialsService sessionCredentialsService;
    private final UserIdentityService userIdentityService;
    private final StoreIdentityService storeIdentityService;
    private final CheckCoiService checkCoiService;

    @ExcludeFromGeneratedCoverageReport
    public IdentityProcessingService(
            TicfCriService ticfCriService,
            AuditService auditService,
            CimitService cimitService,
            CimitUtilityService cimitUtilityService,
            EvaluateGpg45ScoresService evaluateGpg45ScoresService,
            UserIdentityService userIdentityService,
            StoreIdentityService storeIdentityService,
            CheckCoiService checkCoiService,
            SessionCredentialsService sessionCredentialsService,
            CriStoringService criStoringService) {
        this.ticfCriService = ticfCriService;
        this.auditService = auditService;
        this.cimitUtilityService = cimitUtilityService;
        this.cimitService = cimitService;
        this.evaluateGpg45ScoresService = evaluateGpg45ScoresService;
        this.sessionCredentialsService = sessionCredentialsService;
        this.userIdentityService = userIdentityService;
        this.storeIdentityService = storeIdentityService;
        this.checkCoiService = checkCoiService;
        this.criStoringService = criStoringService;
    }

    @ExcludeFromGeneratedCoverageReport
    public IdentityProcessingService(ConfigService configService) {
        this.auditService = AuditService.create(configService);
        this.ticfCriService = new TicfCriService(configService);
        this.cimitUtilityService = new CimitUtilityService(configService);
        this.cimitService = new CimitService(configService);
        this.evaluateGpg45ScoresService =
                new EvaluateGpg45ScoresService(configService, auditService);
        this.sessionCredentialsService = new SessionCredentialsService(configService);
        this.userIdentityService = new UserIdentityService(configService);
        this.storeIdentityService = new StoreIdentityService(configService, auditService);
        this.checkCoiService = new CheckCoiService(configService, auditService);
        this.criStoringService =
                new CriStoringService(
                        configService, auditService, null, sessionCredentialsService, cimitService);
    }

    public static JourneyResponse performIdentityProcessingOperations(
            List<Supplier<JourneyResponse>> operations) {
        for (int i = 0; i < operations.size(); i++) {
            var journeyResponse = operations.get(i).get();

            if (!JOURNEY_NEXT.equals(journeyResponse) || i == operations.size() - 1) {
                return journeyResponse;
            }
        }
        return JOURNEY_NEXT;
    }

    private void logLambdaResponse(String lambdaResult, JourneyResponse journeyResponse) {
        var message =
                new StringMapMessage()
                        .with(LOG_LAMBDA_RESULT.getFieldName(), lambdaResult)
                        .with(LOG_JOURNEY_RESPONSE.getFieldName(), journeyResponse);
        LOGGER.info(message);
    }
}
