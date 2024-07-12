package uk.gov.di.ipv.core.resetsessionidentity;

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
import uk.gov.di.ipv.core.library.enums.SessionCredentialsResetType;
import uk.gov.di.ipv.core.library.exception.EvcsServiceException;
import uk.gov.di.ipv.core.library.exceptions.HttpResponseExceptionWithErrorBody;
import uk.gov.di.ipv.core.library.exceptions.UnknownResetTypeException;
import uk.gov.di.ipv.core.library.exceptions.VerifiableCredentialException;
import uk.gov.di.ipv.core.library.helpers.LogHelper;
import uk.gov.di.ipv.core.library.helpers.RequestHelper;
import uk.gov.di.ipv.core.library.persistence.item.ClientOAuthSessionItem;
import uk.gov.di.ipv.core.library.persistence.item.IpvSessionItem;
import uk.gov.di.ipv.core.library.service.ClientOAuthSessionDetailsService;
import uk.gov.di.ipv.core.library.service.ConfigService;
import uk.gov.di.ipv.core.library.service.CriResponseService;
import uk.gov.di.ipv.core.library.service.EvcsService;
import uk.gov.di.ipv.core.library.service.IpvSessionService;
import uk.gov.di.ipv.core.library.verifiablecredential.service.SessionCredentialsService;
import uk.gov.di.ipv.core.library.verifiablecredential.service.VerifiableCredentialService;

import java.util.Map;

import static org.apache.http.HttpStatus.SC_INTERNAL_SERVER_ERROR;
import static uk.gov.di.ipv.core.library.config.CoreFeatureFlag.EVCS_READ_ENABLED;
import static uk.gov.di.ipv.core.library.config.CoreFeatureFlag.EVCS_WRITE_ENABLED;
import static uk.gov.di.ipv.core.library.domain.Cri.F2F;
import static uk.gov.di.ipv.core.library.domain.ErrorResponse.UNKNOWN_RESET_TYPE;
import static uk.gov.di.ipv.core.library.enums.SessionCredentialsResetType.PENDING_F2F_ALL;
import static uk.gov.di.ipv.core.library.enums.Vot.P0;
import static uk.gov.di.ipv.core.library.helpers.LogHelper.LogField.LOG_RESET_TYPE;
import static uk.gov.di.ipv.core.library.helpers.RequestHelper.getIpvSessionId;
import static uk.gov.di.ipv.core.library.journeyuris.JourneyUris.JOURNEY_ERROR_PATH;
import static uk.gov.di.ipv.core.library.journeyuris.JourneyUris.JOURNEY_NEXT_PATH;

public class ResetSessionIdentityHandler
        implements RequestHandler<ProcessRequest, Map<String, Object>> {
    private static final Logger LOGGER = LogManager.getLogger();
    private static final Map<String, Object> JOURNEY_NEXT =
            new JourneyResponse(JOURNEY_NEXT_PATH).toObjectMap();
    private final ConfigService configService;
    private final IpvSessionService ipvSessionService;
    private final SessionCredentialsService sessionCredentialsService;
    private final ClientOAuthSessionDetailsService clientOAuthSessionDetailsService;
    private final CriResponseService criResponseService;
    private final VerifiableCredentialService verifiableCredentialService;
    private final EvcsService evcsService;

    public ResetSessionIdentityHandler(
            ConfigService configService,
            IpvSessionService ipvSessionService,
            SessionCredentialsService sessionCredentialsService,
            ClientOAuthSessionDetailsService clientOAuthSessionDetailsService,
            CriResponseService criResponseService,
            VerifiableCredentialService verifiableCredentialService,
            EvcsService evcsService) {
        this.configService = configService;
        this.ipvSessionService = ipvSessionService;
        this.sessionCredentialsService = sessionCredentialsService;
        this.clientOAuthSessionDetailsService = clientOAuthSessionDetailsService;
        this.criResponseService = criResponseService;
        this.verifiableCredentialService = verifiableCredentialService;
        this.evcsService = evcsService;
    }

    @ExcludeFromGeneratedCoverageReport
    public ResetSessionIdentityHandler() {
        this.configService = new ConfigService();
        this.ipvSessionService = new IpvSessionService(configService);
        this.sessionCredentialsService = new SessionCredentialsService(configService);
        this.clientOAuthSessionDetailsService = new ClientOAuthSessionDetailsService(configService);
        this.criResponseService = new CriResponseService(configService);
        this.verifiableCredentialService = new VerifiableCredentialService(configService);
        this.evcsService = new EvcsService(configService);
    }

    @Override
    @Tracing
    @Logging(clearState = true)
    public Map<String, Object> handleRequest(ProcessRequest input, Context context) {
        LogHelper.attachComponentId(configService);
        configService.setFeatureSet(RequestHelper.getFeatureSet(input));

        try {
            String ipvSessionId = getIpvSessionId(input);
            IpvSessionItem ipvSessionItem = ipvSessionService.getIpvSession(ipvSessionId);

            ClientOAuthSessionItem clientOAuthSessionItem =
                    clientOAuthSessionDetailsService.getClientOAuthSession(
                            ipvSessionItem.getClientOAuthSessionId());
            String govukSigninJourneyId = clientOAuthSessionItem.getGovukSigninJourneyId();
            LogHelper.attachGovukSigninJourneyIdToLogs(govukSigninJourneyId);

            ipvSessionItem.setVot(P0);
            ipvSessionService.updateIpvSession(ipvSessionItem);

            SessionCredentialsResetType sessionCredentialsResetType =
                    RequestHelper.getSessionCredentialsResetType(input);
            sessionCredentialsService.deleteSessionCredentialsForResetType(
                    ipvSessionId, sessionCredentialsResetType);
            LOGGER.info(LogHelper.buildLogMessage("Session credentials deleted"));

            if (sessionCredentialsResetType.equals(PENDING_F2F_ALL)) {
                doResetForPendingF2f(clientOAuthSessionItem);
            }

            return JOURNEY_NEXT;
        } catch (HttpResponseExceptionWithErrorBody
                | VerifiableCredentialException
                | EvcsServiceException e) {
            LOGGER.error(LogHelper.buildErrorMessage(e.getErrorResponse().getMessage(), e));
            return new JourneyErrorResponse(
                            JOURNEY_ERROR_PATH, e.getResponseCode(), e.getErrorResponse())
                    .toObjectMap();
        } catch (UnknownResetTypeException e) {
            LOGGER.error(
                    LogHelper.buildErrorMessage("Unknown reset type received", e)
                            .with(LOG_RESET_TYPE.getFieldName(), e.getResetType()));
            return new JourneyErrorResponse(
                            JOURNEY_ERROR_PATH, SC_INTERNAL_SERVER_ERROR, UNKNOWN_RESET_TYPE)
                    .toObjectMap();
        }
    }

    private void doResetForPendingF2f(ClientOAuthSessionItem clientOAuthSessionItem)
            throws VerifiableCredentialException, EvcsServiceException {
        String userId = clientOAuthSessionItem.getUserId();
        criResponseService.deleteCriResponseItem(userId, F2F);
        verifiableCredentialService.deleteVCs(userId);
        updateEvcsPendingIdentity(userId, clientOAuthSessionItem.getEvcsAccessToken());
        LOGGER.info(LogHelper.buildLogMessage("Reset done for F2F pending identity."));
    }

    private void updateEvcsPendingIdentity(String userId, String evcsAccessToken)
            throws EvcsServiceException {
        try {
            if (configService.enabled(EVCS_WRITE_ENABLED)) {
                evcsService.updatePendingIdentity(userId, evcsAccessToken);
            }
        } catch (EvcsServiceException e) {
            if (configService.enabled(EVCS_READ_ENABLED)) {
                throw e;
            } else {
                LOGGER.error(LogHelper.buildErrorMessage("Failed to update EVCS identity", e));
            }
        }
    }
}
