package uk.gov.di.ipv.core.processcandidateidentity.service;

import org.apache.http.HttpStatus;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.apache.logging.log4j.message.StringMapMessage;
import uk.gov.di.ipv.core.library.cimit.exception.CiPostMitigationsException;
import uk.gov.di.ipv.core.library.cimit.exception.CiPutException;
import uk.gov.di.ipv.core.library.cimit.exception.CiRetrievalException;
import uk.gov.di.ipv.core.library.cristoringservice.CriStoringService;
import uk.gov.di.ipv.core.library.domain.JourneyErrorResponse;
import uk.gov.di.ipv.core.library.domain.JourneyResponse;
import uk.gov.di.ipv.core.library.enums.CoiCheckType;
import uk.gov.di.ipv.core.library.enums.IdentityType;
import uk.gov.di.ipv.core.library.enums.Vot;
import uk.gov.di.ipv.core.library.exception.EvcsServiceException;
import uk.gov.di.ipv.core.library.exceptions.ConfigException;
import uk.gov.di.ipv.core.library.exceptions.CredentialParseException;
import uk.gov.di.ipv.core.library.exceptions.HttpResponseExceptionWithErrorBody;
import uk.gov.di.ipv.core.library.exceptions.UnrecognisedVotException;
import uk.gov.di.ipv.core.library.exceptions.VerifiableCredentialException;
import uk.gov.di.ipv.core.library.helpers.LogHelper;
import uk.gov.di.ipv.core.library.journeys.JourneyUris;
import uk.gov.di.ipv.core.library.persistence.item.ClientOAuthSessionItem;
import uk.gov.di.ipv.core.library.persistence.item.IpvSessionItem;
import uk.gov.di.ipv.core.library.service.AuditService;
import uk.gov.di.ipv.core.library.service.CimitService;
import uk.gov.di.ipv.core.library.service.CimitUtilityService;
import uk.gov.di.ipv.core.library.service.ConfigService;
import uk.gov.di.ipv.core.library.service.UserIdentityService;
import uk.gov.di.ipv.core.library.verifiablecredential.service.SessionCredentialsService;
import uk.gov.di.ipv.core.processcandidateidentity.exception.TicfCriServiceException;
import uk.gov.di.model.ContraIndicator;

import java.util.List;
import java.util.function.Supplier;

import static org.apache.http.HttpStatus.SC_INTERNAL_SERVER_ERROR;
import static uk.gov.di.ipv.core.library.domain.Cri.TICF;
import static uk.gov.di.ipv.core.library.domain.ErrorResponse.ERROR_PROCESSING_TICF_CRI_RESPONSE;
import static uk.gov.di.ipv.core.library.domain.ErrorResponse.FAILED_TO_GET_STORED_CIS;
import static uk.gov.di.ipv.core.library.domain.ErrorResponse.FAILED_TO_PARSE_ISSUED_CREDENTIALS;
import static uk.gov.di.ipv.core.library.helpers.LogHelper.LogField.LOG_JOURNEY_RESPONSE;
import static uk.gov.di.ipv.core.library.helpers.LogHelper.LogField.LOG_LAMBDA_RESULT;
import static uk.gov.di.ipv.core.library.journeys.JourneyUris.JOURNEY_COI_CHECK_FAILED_PATH;
import static uk.gov.di.ipv.core.library.journeys.JourneyUris.JOURNEY_ERROR_PATH;
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

    public IdentityProcessingService(ConfigService configService) {
        this.ticfCriService = new TicfCriService(configService);
        this.auditService = AuditService.create(configService);
        this.cimitUtilityService = new CimitUtilityService(configService);
        this.cimitService = new CimitService(configService);
        this.evaluateGpg45ScoresService = new EvaluateGpg45ScoresService(configService);
        this.sessionCredentialsService = new SessionCredentialsService(configService);
        this.userIdentityService = new UserIdentityService(configService);
        this.storeIdentityService = new StoreIdentityService(configService);
        this.checkCoiService = new CheckCoiService(configService);
        this.criStoringService =
                new CriStoringService(
                        configService, auditService, null, sessionCredentialsService, cimitService);
    }

    public JourneyResponse getJourneyResponseFromTicfCall(
            IpvSessionItem ipvSessionItem,
            ClientOAuthSessionItem clientOAuthSessionItem,
            String deviceInformation,
            String ipAddress) {
        try {
            var ticfVcs = ticfCriService.getTicfVc(clientOAuthSessionItem, ipvSessionItem);

            if (ticfVcs.isEmpty()) {
                LOGGER.warn(LogHelper.buildLogMessage("No TICF VC to process - returning next"));
                return JOURNEY_NEXT;
            }

            criStoringService.storeVcs(
                    TICF,
                    ipAddress,
                    deviceInformation,
                    ticfVcs,
                    clientOAuthSessionItem,
                    ipvSessionItem);

            List<ContraIndicator> cis =
                    cimitService.getContraIndicators(
                            clientOAuthSessionItem.getUserId(),
                            clientOAuthSessionItem.getGovukSigninJourneyId(),
                            ipAddress);

            var thresholdVot = ipvSessionItem.getThresholdVot();

            var journeyResponse =
                    cimitUtilityService.getMitigationJourneyIfBreaching(cis, thresholdVot);
            if (journeyResponse.isPresent()) {
                LOGGER.info(
                        LogHelper.buildLogMessage(
                                "CI score is breaching threshold - setting VOT to P0"));
                ipvSessionItem.setVot(Vot.P0);

                return journeyResponse.get();
            }

            LOGGER.info(LogHelper.buildLogMessage("CI score not breaching threshold"));
            return JOURNEY_NEXT;
        } catch (TicfCriServiceException
                | VerifiableCredentialException
                | CiPostMitigationsException
                | CiPutException
                | CiRetrievalException
                | ConfigException
                | UnrecognisedVotException e) {
            LOGGER.error(LogHelper.buildErrorMessage("Error processing response from TICF CRI", e));
            return new JourneyErrorResponse(
                    JOURNEY_ERROR_PATH,
                    HttpStatus.SC_INTERNAL_SERVER_ERROR,
                    ERROR_PROCESSING_TICF_CRI_RESPONSE);
        }
    }

    public JourneyResponse getJourneyResponseFromGpg45ScoreEvaluation(
            IpvSessionItem ipvSessionItem,
            ClientOAuthSessionItem clientOAuthSessionItem,
            String deviceInformation,
            String ipAddress) {
        String userId = clientOAuthSessionItem.getUserId();

        try {

            var vcs =
                    sessionCredentialsService.getCredentials(
                            ipvSessionItem.getIpvSessionId(), userId);

            if (!userIdentityService.areVcsCorrelated(vcs)) {
                return JOURNEY_VCS_NOT_CORRELATED;
            }

            // This is a performance optimisation as calling cimitService.getContraIndicators()
            // takes about 0.5 seconds.
            // If the VTR only contains one entry then it is impossible for a user to reach here
            // with a breaching CI so we don't have to check.
            var contraIndicators =
                    clientOAuthSessionItem.getVtr().size() == 1
                            ? null
                            : cimitService.getContraIndicators(
                                    clientOAuthSessionItem.getUserId(),
                                    clientOAuthSessionItem.getGovukSigninJourneyId(),
                                    ipAddress);

            var matchingGpg45Profile =
                    evaluateGpg45ScoresService.findMatchingGpg45Profile(
                            vcs,
                            ipvSessionItem,
                            clientOAuthSessionItem,
                            ipAddress,
                            deviceInformation,
                            contraIndicators);

            if (matchingGpg45Profile.isEmpty()) {
                logLambdaResponse("No GPG45 profiles have been met", JOURNEY_GPG45_UNMET);
                return JOURNEY_GPG45_UNMET;
            }

            ipvSessionItem.setVot(Vot.fromGpg45Profile(matchingGpg45Profile.get()));
            logLambdaResponse("A GPG45 profile has been met", JOURNEY_NEXT);
            return JOURNEY_NEXT;
        } catch (HttpResponseExceptionWithErrorBody | VerifiableCredentialException e) {
            LOGGER.error(LogHelper.buildErrorMessage("Received exception", e));
            return new JourneyErrorResponse(
                    JOURNEY_ERROR_PATH, e.getResponseCode(), e.getErrorResponse());
        } catch (CiRetrievalException e) {
            LOGGER.error(LogHelper.buildErrorMessage(FAILED_TO_GET_STORED_CIS.getMessage(), e));
            return new JourneyErrorResponse(
                    JOURNEY_ERROR_PATH,
                    HttpStatus.SC_INTERNAL_SERVER_ERROR,
                    FAILED_TO_GET_STORED_CIS);
        }
    }

    public JourneyResponse getJourneyResponseFromStoringIdentity(
            IpvSessionItem ipvSessionItem,
            ClientOAuthSessionItem clientOAuthSessionItem,
            IdentityType identityType,
            String deviceInformation,
            String ipAddress) {
        try {
            storeIdentityService.storeIdentity(
                    ipvSessionItem,
                    clientOAuthSessionItem,
                    identityType,
                    deviceInformation,
                    ipAddress);

            return JOURNEY_NEXT;
        } catch (VerifiableCredentialException | EvcsServiceException e) {
            LOGGER.error(LogHelper.buildErrorMessage("Failed to store identity", e));
            return new JourneyErrorResponse(
                    JOURNEY_ERROR_PATH, e.getResponseCode(), e.getErrorResponse());
        }
    }

    public JourneyResponse getJourneyResponseFromCoiCheck(
            IpvSessionItem ipvSessionItem,
            ClientOAuthSessionItem clientOAuthSessionItem,
            CoiCheckType coiCheckType,
            String deviceInformation,
            String ipAddress) {
        try {
            return checkCoiService.isCoiCheckSuccessful(
                            ipvSessionItem,
                            clientOAuthSessionItem,
                            coiCheckType,
                            deviceInformation,
                            ipAddress)
                    ? JOURNEY_NEXT
                    : JOURNEY_COI_CHECK_FAILED;
        } catch (HttpResponseExceptionWithErrorBody
                | EvcsServiceException
                | VerifiableCredentialException e) {
            LOGGER.error(LogHelper.buildErrorMessage("Received exception", e));
            return new JourneyErrorResponse(
                    JOURNEY_ERROR_PATH, e.getResponseCode(), e.getErrorResponse());
        } catch (CredentialParseException e) {
            LOGGER.error(LogHelper.buildErrorMessage("Unable to parse existing credentials", e));
            return new JourneyErrorResponse(
                    JOURNEY_ERROR_PATH,
                    SC_INTERNAL_SERVER_ERROR,
                    FAILED_TO_PARSE_ISSUED_CREDENTIALS);
        }
    }

    public JourneyResponse performIdentityProcessingOperations(
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
