package uk.gov.di.ipv.core.calldcmawasynccri;

import com.amazonaws.services.lambda.runtime.Context;
import com.amazonaws.services.lambda.runtime.RequestHandler;
import com.nimbusds.oauth2.sdk.http.HTTPResponse;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import software.amazon.awssdk.http.HttpStatusCode;
import software.amazon.lambda.powertools.logging.Logging;
import software.amazon.lambda.powertools.metrics.Metrics;
import uk.gov.di.ipv.core.calldcmawasynccri.exception.DcmawAsyncCriHttpResponseException;
import uk.gov.di.ipv.core.calldcmawasynccri.service.DcmawAsyncCriService;
import uk.gov.di.ipv.core.library.annotations.ExcludeFromGeneratedCoverageReport;
import uk.gov.di.ipv.core.library.cimit.service.CimitService;
import uk.gov.di.ipv.core.library.criresponse.service.CriResponseService;
import uk.gov.di.ipv.core.library.cristoringservice.CriStoringService;
import uk.gov.di.ipv.core.library.domain.JourneyErrorResponse;
import uk.gov.di.ipv.core.library.domain.JourneyResponse;
import uk.gov.di.ipv.core.library.domain.ProcessRequest;
import uk.gov.di.ipv.core.library.enums.MobileAppJourneyType;
import uk.gov.di.ipv.core.library.exceptions.HttpResponseExceptionWithErrorBody;
import uk.gov.di.ipv.core.library.exceptions.VerifiableCredentialException;
import uk.gov.di.ipv.core.library.helpers.LogHelper;
import uk.gov.di.ipv.core.library.helpers.RequestHelper;
import uk.gov.di.ipv.core.library.helpers.SecureTokenHelper;
import uk.gov.di.ipv.core.library.persistence.item.ClientOAuthSessionItem;
import uk.gov.di.ipv.core.library.persistence.item.IpvSessionItem;
import uk.gov.di.ipv.core.library.service.AuditService;
import uk.gov.di.ipv.core.library.service.ClientOAuthSessionDetailsService;
import uk.gov.di.ipv.core.library.service.ConfigService;
import uk.gov.di.ipv.core.library.service.IpvSessionService;
import uk.gov.di.ipv.core.library.verifiablecredential.domain.VerifiableCredentialResponse;
import uk.gov.di.ipv.core.library.verifiablecredential.domain.VerifiableCredentialStatus;
import uk.gov.di.ipv.core.library.verifiablecredential.service.SessionCredentialsService;

import java.util.List;
import java.util.Map;

import static uk.gov.di.ipv.core.library.domain.Cri.DCMAW_ASYNC;
import static uk.gov.di.ipv.core.library.domain.ErrorResponse.ERROR_CALLING_DCMAW_ASYNC_CRI;
import static uk.gov.di.ipv.core.library.domain.ErrorResponse.FAILED_TO_VALIDATE_VERIFIABLE_CREDENTIAL_RESPONSE;
import static uk.gov.di.ipv.core.library.journeys.JourneyUris.JOURNEY_ERROR_PATH;
import static uk.gov.di.ipv.core.library.journeys.JourneyUris.JOURNEY_NEXT_PATH;

public class CallDcmawAsyncCriHandler
        implements RequestHandler<ProcessRequest, Map<String, Object>> {
    private static final Logger LOGGER = LogManager.getLogger();
    private static final Map<String, Object> JOURNEY_NEXT =
            new JourneyResponse(JOURNEY_NEXT_PATH).toObjectMap();

    private final ConfigService configService;
    private final IpvSessionService ipvSessionService;
    private final ClientOAuthSessionDetailsService clientOAuthSessionDetailsService;
    private final DcmawAsyncCriService dcmawAsyncCriService;
    private final CriStoringService criStoringService;
    private final AuditService auditService;

    @ExcludeFromGeneratedCoverageReport
    public CallDcmawAsyncCriHandler() {
        this(ConfigService.create());
    }

    @ExcludeFromGeneratedCoverageReport
    public CallDcmawAsyncCriHandler(ConfigService configService) {
        this.configService = configService;
        this.ipvSessionService = new IpvSessionService(configService);
        this.clientOAuthSessionDetailsService = new ClientOAuthSessionDetailsService(configService);
        this.auditService = AuditService.create(configService);
        this.dcmawAsyncCriService = new DcmawAsyncCriService(configService, auditService);
        this.criStoringService =
                new CriStoringService(
                        configService,
                        auditService,
                        new CriResponseService(configService),
                        new SessionCredentialsService(configService),
                        new CimitService(configService));
    }

    public CallDcmawAsyncCriHandler(
            ConfigService configService,
            IpvSessionService ipvSessionService,
            ClientOAuthSessionDetailsService clientOAuthSessionDetailsService,
            DcmawAsyncCriService dcmawAsyncCriService,
            CriStoringService criStoringService,
            AuditService auditService) {
        this.configService = configService;
        this.ipvSessionService = ipvSessionService;
        this.clientOAuthSessionDetailsService = clientOAuthSessionDetailsService;
        this.dcmawAsyncCriService = dcmawAsyncCriService;
        this.criStoringService = criStoringService;
        this.auditService = auditService;
    }

    @Override
    @Logging(clearState = true)
    @Metrics(captureColdStart = true)
    public Map<String, Object> handleRequest(ProcessRequest request, Context context) {
        LogHelper.attachTraceId();
        LogHelper.attachComponentId(configService);
        LogHelper.attachCriIdToLogs(DCMAW_ASYNC);
        List<String> featureSets = RequestHelper.getFeatureSet(request);
        configService.setFeatureSet(featureSets);

        IpvSessionItem ipvSessionItem = null;
        try {
            final String ipvSessionId = RequestHelper.getIpvSessionId(request);
            ipvSessionItem = ipvSessionService.getIpvSession(ipvSessionId);
            final MobileAppJourneyType mobileAppJourneyType =
                    RequestHelper.getMobileAppJourneyType(request);

            final String clientOAuthSessionId = ipvSessionItem.getClientOAuthSessionId();
            ClientOAuthSessionItem clientOAuthSessionItem =
                    clientOAuthSessionDetailsService.getClientOAuthSession(clientOAuthSessionId);

            LogHelper.attachGovukSigninJourneyIdToLogs(
                    clientOAuthSessionItem.getGovukSigninJourneyId());

            String oauthState = SecureTokenHelper.getInstance().generate();

            var vcResponse =
                    dcmawAsyncCriService.startDcmawAsyncSession(
                            oauthState,
                            clientOAuthSessionItem,
                            ipvSessionItem,
                            mobileAppJourneyType);

            if (!VerifiableCredentialStatus.PENDING.equals(vcResponse.getCredentialStatus())) {
                throw new DcmawAsyncCriHttpResponseException(
                        "DCMAW Async CRI returned a non-pending VC response");
            }

            validatePendingVcResponse(vcResponse, clientOAuthSessionItem);
            criStoringService.recordCriResponse(
                    request, DCMAW_ASYNC, oauthState, clientOAuthSessionItem, featureSets);

            dcmawAsyncCriService.sendAuditEventForAppHandoff(request, clientOAuthSessionItem);

            return JOURNEY_NEXT;
        } catch (HttpResponseExceptionWithErrorBody e) {
            LOGGER.error(LogHelper.buildErrorMessage(e.getErrorResponse()));
            return new JourneyErrorResponse(
                            JOURNEY_ERROR_PATH, e.getResponseCode(), e.getErrorResponse())
                    .toObjectMap();
        } catch (Exception e) {
            LOGGER.error(LogHelper.buildErrorMessage("Error calling DCMAW Async CRI", e));
            return new JourneyErrorResponse(
                            JOURNEY_ERROR_PATH,
                            HttpStatusCode.INTERNAL_SERVER_ERROR,
                            ERROR_CALLING_DCMAW_ASYNC_CRI)
                    .toObjectMap();
        } finally {
            if (ipvSessionItem != null) {
                ipvSessionService.updateIpvSession(ipvSessionItem);
            }
            auditService.awaitAuditEvents();
        }
    }

    private void validatePendingVcResponse(
            VerifiableCredentialResponse vcResponse, ClientOAuthSessionItem clientOAuthSessionItem)
            throws VerifiableCredentialException {
        var userId = clientOAuthSessionItem.getUserId();

        if (!vcResponse.getUserId().equals(userId)) {
            throw new VerifiableCredentialException(
                    HTTPResponse.SC_SERVER_ERROR,
                    FAILED_TO_VALIDATE_VERIFIABLE_CREDENTIAL_RESPONSE);
        }
    }
}
