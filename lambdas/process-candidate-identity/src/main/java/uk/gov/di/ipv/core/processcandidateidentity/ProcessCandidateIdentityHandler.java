package uk.gov.di.ipv.core.processcandidateidentity;

import com.amazonaws.services.lambda.runtime.Context;
import com.amazonaws.services.lambda.runtime.RequestHandler;
import org.apache.http.HttpStatus;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import software.amazon.lambda.powertools.logging.Logging;
import software.amazon.lambda.powertools.tracing.Tracing;
import uk.gov.di.ipv.core.library.annotations.ExcludeFromGeneratedCoverageReport;
import uk.gov.di.ipv.core.library.domain.Cri;
import uk.gov.di.ipv.core.library.domain.JourneyErrorResponse;
import uk.gov.di.ipv.core.library.domain.JourneyResponse;
import uk.gov.di.ipv.core.library.domain.ProcessRequest;
import uk.gov.di.ipv.core.library.enums.CoiCheckType;
import uk.gov.di.ipv.core.library.enums.IdentityType;
import uk.gov.di.ipv.core.library.exceptions.HttpResponseExceptionWithErrorBody;
import uk.gov.di.ipv.core.library.exceptions.IpvSessionNotFoundException;
import uk.gov.di.ipv.core.library.exceptions.UnknownCoiCheckTypeException;
import uk.gov.di.ipv.core.library.exceptions.UnknownProcessIdentityType;
import uk.gov.di.ipv.core.library.helpers.LogHelper;
import uk.gov.di.ipv.core.library.helpers.RequestHelper;
import uk.gov.di.ipv.core.library.persistence.item.ClientOAuthSessionItem;
import uk.gov.di.ipv.core.library.persistence.item.IpvSessionItem;
import uk.gov.di.ipv.core.library.service.AuditService;
import uk.gov.di.ipv.core.library.service.ClientOAuthSessionDetailsService;
import uk.gov.di.ipv.core.library.service.ConfigService;
import uk.gov.di.ipv.core.library.service.IpvSessionService;
import uk.gov.di.ipv.core.processcandidateidentity.service.IdentityProcessingService;

import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.function.Supplier;

import static org.apache.http.HttpStatus.SC_INTERNAL_SERVER_ERROR;
import static uk.gov.di.ipv.core.library.config.ConfigurationVariable.CREDENTIAL_ISSUER_ENABLED;
import static uk.gov.di.ipv.core.library.domain.ErrorResponse.IPV_SESSION_NOT_FOUND;
import static uk.gov.di.ipv.core.library.domain.ErrorResponse.UNEXPECTED_PROCESS_IDENTITY_TYPE;
import static uk.gov.di.ipv.core.library.domain.ErrorResponse.UNKNOWN_CHECK_TYPE;
import static uk.gov.di.ipv.core.library.helpers.LogHelper.LogField.LOG_CHECK_TYPE;
import static uk.gov.di.ipv.core.library.journeys.JourneyUris.JOURNEY_ERROR_PATH;

public class ProcessCandidateIdentityHandler
        implements RequestHandler<ProcessRequest, Map<String, Object>> {
    private static final Logger LOGGER = LogManager.getLogger();

    private final ConfigService configService;
    private final ClientOAuthSessionDetailsService clientOAuthSessionDetailsService;
    private final IpvSessionService ipvSessionService;
    private final IdentityProcessingService identityProcessingService;
    private final AuditService auditService;

    @ExcludeFromGeneratedCoverageReport
    public ProcessCandidateIdentityHandler() {
        this(ConfigService.create());
    }

    public ProcessCandidateIdentityHandler(ConfigService configService) {
        this.configService = configService;
        this.clientOAuthSessionDetailsService = new ClientOAuthSessionDetailsService(configService);
        this.ipvSessionService = new IpvSessionService(configService);
        this.identityProcessingService = new IdentityProcessingService(configService);
        this.auditService = AuditService.create(configService);
    }

    @Override
    @Tracing
    @Logging
    public Map<String, Object> handleRequest(ProcessRequest request, Context context) {
        LogHelper.attachComponentId(configService);
        configService.setFeatureSet(RequestHelper.getFeatureSet(request));

        IpvSessionItem ipvSessionItem = null;
        try {
            var ipvSessionId = RequestHelper.getIpvSessionId(request);
            var ipAddress = RequestHelper.getIpAddress(request);
            var deviceInformation = request.getDeviceInformation();
            var processIdentityType = RequestHelper.getProcessIdentityType(request);

            ipvSessionItem = ipvSessionService.getIpvSession(ipvSessionId);
            ClientOAuthSessionItem clientOAuthSessionItem =
                    clientOAuthSessionDetailsService.getClientOAuthSession(
                            ipvSessionItem.getClientOAuthSessionId());

            String govukSigninJourneyId = clientOAuthSessionItem.getGovukSigninJourneyId();
            LogHelper.attachGovukSigninJourneyIdToLogs(govukSigninJourneyId);

            return switch (processIdentityType) {
                case ALL -> processIdentityAll(
                                ipvSessionItem,
                                clientOAuthSessionItem,
                                request,
                                deviceInformation,
                                ipAddress)
                        .toObjectMap();
                case COI -> processIdentityCoi(
                                ipvSessionItem,
                                clientOAuthSessionItem,
                                request,
                                deviceInformation,
                                ipAddress)
                        .toObjectMap();
                case STORE_IDENTITY -> processIdentityStoreIdentity(
                                ipvSessionItem,
                                clientOAuthSessionItem,
                                request,
                                deviceInformation,
                                ipAddress)
                        .toObjectMap();
                case TICF_ONLY -> processIdentityTicfOnly(
                                ipvSessionItem,
                                clientOAuthSessionItem,
                                deviceInformation,
                                ipAddress)
                        .toObjectMap();
            };

        } catch (HttpResponseExceptionWithErrorBody e) {
            LOGGER.error(LogHelper.buildErrorMessage("Failed to process identity", e));
            return new JourneyErrorResponse(
                            JOURNEY_ERROR_PATH, e.getResponseCode(), e.getErrorResponse())
                    .toObjectMap();
        } catch (UnknownProcessIdentityType e) {
            LOGGER.error(LogHelper.buildErrorMessage("Unknown process identity type", e));
            return new JourneyErrorResponse(
                            JOURNEY_ERROR_PATH,
                            HttpStatus.SC_INTERNAL_SERVER_ERROR,
                            UNEXPECTED_PROCESS_IDENTITY_TYPE)
                    .toObjectMap();
        } catch (IpvSessionNotFoundException e) {
            LOGGER.error(LogHelper.buildErrorMessage("Failed to find ipv session", e));
            return new JourneyErrorResponse(
                            JOURNEY_ERROR_PATH,
                            HttpStatus.SC_INTERNAL_SERVER_ERROR,
                            IPV_SESSION_NOT_FOUND)
                    .toObjectMap();
        } catch (UnknownCoiCheckTypeException e) {
            LOGGER.error(
                    LogHelper.buildErrorMessage("Unknown COI check type received", e)
                            .with(LOG_CHECK_TYPE.getFieldName(), e.getCheckType()));
            return new JourneyErrorResponse(
                            JOURNEY_ERROR_PATH, SC_INTERNAL_SERVER_ERROR, UNKNOWN_CHECK_TYPE)
                    .toObjectMap();
        } catch (Exception e) {
            LOGGER.error(LogHelper.buildErrorMessage("Unhandled lambda exception", e));
            throw e;
        } finally {
            if (ipvSessionItem != null) {
                ipvSessionService.updateIpvSession(ipvSessionItem);
            }
            auditService.awaitAuditEvents();
        }
    }

    private JourneyResponse processIdentityAll(
            IpvSessionItem ipvSessionItem,
            ClientOAuthSessionItem clientOAuthSessionItem,
            ProcessRequest request,
            String deviceInformation,
            String ipAddress)
            throws HttpResponseExceptionWithErrorBody, UnknownCoiCheckTypeException {
        var coiCheckType = getCoiCheckTypeFromRequest(request);
        var identityType = getIdentityTypeFromRequest(request);

        return identityProcessingService.performIdentityProcessingOperations(
                List.of(
                        () ->
                                identityProcessingService.getJourneyResponseFromCoiCheck(
                                        ipvSessionItem,
                                        clientOAuthSessionItem,
                                        coiCheckType,
                                        deviceInformation,
                                        ipAddress),
                        () ->
                                identityProcessingService
                                        .getJourneyResponseFromGpg45ScoreEvaluation(
                                                ipvSessionItem,
                                                clientOAuthSessionItem,
                                                deviceInformation,
                                                ipAddress),
                        () ->
                                identityProcessingService.getJourneyResponseFromTicfCall(
                                        ipvSessionItem,
                                        clientOAuthSessionItem,
                                        deviceInformation,
                                        ipAddress),
                        () ->
                                identityProcessingService.getJourneyResponseFromStoringIdentity(
                                        ipvSessionItem,
                                        clientOAuthSessionItem,
                                        identityType,
                                        deviceInformation,
                                        ipAddress)));
    }

    private JourneyResponse processIdentityCoi(
            IpvSessionItem ipvSessionItem,
            ClientOAuthSessionItem clientOAuthSessionItem,
            ProcessRequest request,
            String deviceInformation,
            String ipAddress)
            throws HttpResponseExceptionWithErrorBody, UnknownCoiCheckTypeException {
        var coiCheckType = getCoiCheckTypeFromRequest(request);

        List<Supplier<JourneyResponse>> operations =
                new ArrayList<>(
                        List.of(
                                () ->
                                        identityProcessingService.getJourneyResponseFromCoiCheck(
                                                ipvSessionItem,
                                                clientOAuthSessionItem,
                                                coiCheckType,
                                                deviceInformation,
                                                ipAddress)));

        if (configService.getBooleanParameter(CREDENTIAL_ISSUER_ENABLED, Cri.TICF.getId())) {
            operations.add(
                    () ->
                            identityProcessingService.getJourneyResponseFromTicfCall(
                                    ipvSessionItem,
                                    clientOAuthSessionItem,
                                    deviceInformation,
                                    ipAddress));
        }

        return identityProcessingService.performIdentityProcessingOperations(operations);
    }

    private JourneyResponse processIdentityStoreIdentity(
            IpvSessionItem ipvSessionItem,
            ClientOAuthSessionItem clientOAuthSessionItem,
            ProcessRequest request,
            String deviceInformation,
            String ipAddress)
            throws HttpResponseExceptionWithErrorBody {
        var identityType = getIdentityTypeFromRequest(request);

        List<Supplier<JourneyResponse>> operations =
                new ArrayList<>(
                        List.of(
                                () ->
                                        identityProcessingService
                                                .getJourneyResponseFromStoringIdentity(
                                                        ipvSessionItem,
                                                        clientOAuthSessionItem,
                                                        identityType,
                                                        deviceInformation,
                                                        ipAddress)));

        if (configService.getBooleanParameter(CREDENTIAL_ISSUER_ENABLED, Cri.TICF.getId())) {
            operations.add(
                    () ->
                            identityProcessingService.getJourneyResponseFromTicfCall(
                                    ipvSessionItem,
                                    clientOAuthSessionItem,
                                    deviceInformation,
                                    ipAddress));
        }

        return identityProcessingService.performIdentityProcessingOperations(operations);
    }

    private JourneyResponse processIdentityTicfOnly(
            IpvSessionItem ipvSessionItem,
            ClientOAuthSessionItem clientOAuthSessionItem,
            String deviceInformation,
            String ipAddress) {
        return identityProcessingService.performIdentityProcessingOperations(
                List.of(
                        () ->
                                identityProcessingService.getJourneyResponseFromTicfCall(
                                        ipvSessionItem,
                                        clientOAuthSessionItem,
                                        deviceInformation,
                                        ipAddress)));
    }

    private CoiCheckType getCoiCheckTypeFromRequest(ProcessRequest request)
            throws HttpResponseExceptionWithErrorBody, UnknownCoiCheckTypeException {
        return RequestHelper.getCoiCheckType(request);
    }

    private IdentityType getIdentityTypeFromRequest(ProcessRequest request)
            throws HttpResponseExceptionWithErrorBody {
        return RequestHelper.getIdentityType(request);
    }
}
