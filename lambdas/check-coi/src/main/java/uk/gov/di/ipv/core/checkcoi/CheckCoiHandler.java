package uk.gov.di.ipv.core.checkcoi;

import com.amazonaws.services.lambda.runtime.Context;
import com.amazonaws.services.lambda.runtime.RequestHandler;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import software.amazon.awssdk.http.HttpStatusCode;
import software.amazon.lambda.powertools.logging.Logging;
import software.amazon.lambda.powertools.metrics.Metrics;
import uk.gov.di.ipv.core.library.annotations.ExcludeFromGeneratedCoverageReport;
import uk.gov.di.ipv.core.library.auditing.AuditEvent;
import uk.gov.di.ipv.core.library.auditing.AuditEventTypes;
import uk.gov.di.ipv.core.library.auditing.AuditEventUser;
import uk.gov.di.ipv.core.library.auditing.extension.AuditExtensionCoiCheck;
import uk.gov.di.ipv.core.library.auditing.restricted.AuditRestrictedCheckCoi;
import uk.gov.di.ipv.core.library.auditing.restricted.AuditRestrictedDeviceInformation;
import uk.gov.di.ipv.core.library.auditing.restricted.DeviceInformation;
import uk.gov.di.ipv.core.library.config.ConfigurationVariable;
import uk.gov.di.ipv.core.library.domain.ErrorResponse;
import uk.gov.di.ipv.core.library.domain.IdentityClaim;
import uk.gov.di.ipv.core.library.domain.JourneyErrorResponse;
import uk.gov.di.ipv.core.library.domain.JourneyResponse;
import uk.gov.di.ipv.core.library.domain.ProcessRequest;
import uk.gov.di.ipv.core.library.domain.ReverificationFailureCode;
import uk.gov.di.ipv.core.library.domain.ReverificationStatus;
import uk.gov.di.ipv.core.library.domain.VerifiableCredential;
import uk.gov.di.ipv.core.library.enums.CoiCheckType;
import uk.gov.di.ipv.core.library.evcs.exception.EvcsServiceException;
import uk.gov.di.ipv.core.library.evcs.service.EvcsService;
import uk.gov.di.ipv.core.library.exceptions.CredentialParseException;
import uk.gov.di.ipv.core.library.exceptions.HttpResponseExceptionWithErrorBody;
import uk.gov.di.ipv.core.library.exceptions.IpvSessionNotFoundException;
import uk.gov.di.ipv.core.library.exceptions.UnknownCoiCheckTypeException;
import uk.gov.di.ipv.core.library.exceptions.VerifiableCredentialException;
import uk.gov.di.ipv.core.library.helpers.LogHelper;
import uk.gov.di.ipv.core.library.helpers.RequestHelper;
import uk.gov.di.ipv.core.library.persistence.item.ClientOAuthSessionItem;
import uk.gov.di.ipv.core.library.persistence.item.IpvSessionItem;
import uk.gov.di.ipv.core.library.service.AuditService;
import uk.gov.di.ipv.core.library.service.ClientOAuthSessionDetailsService;
import uk.gov.di.ipv.core.library.service.ConfigService;
import uk.gov.di.ipv.core.library.service.IpvSessionService;
import uk.gov.di.ipv.core.library.useridentity.service.UserIdentityService;
import uk.gov.di.ipv.core.library.verifiablecredential.service.SessionCredentialsService;
import uk.gov.di.model.PostalAddress;

import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.stream.Stream;

import static java.lang.Boolean.TRUE;
import static uk.gov.di.ipv.core.library.domain.ErrorResponse.FAILED_TO_PARSE_ISSUED_CREDENTIALS;
import static uk.gov.di.ipv.core.library.domain.ErrorResponse.IPV_SESSION_NOT_FOUND;
import static uk.gov.di.ipv.core.library.domain.ErrorResponse.UNKNOWN_CHECK_TYPE;
import static uk.gov.di.ipv.core.library.evcs.enums.EvcsVCState.CURRENT;
import static uk.gov.di.ipv.core.library.helpers.LogHelper.LogField.LOG_CHECK_TYPE;
import static uk.gov.di.ipv.core.library.journeys.JourneyUris.JOURNEY_COI_CHECK_FAILED_PATH;
import static uk.gov.di.ipv.core.library.journeys.JourneyUris.JOURNEY_COI_CHECK_PASSED_PATH;
import static uk.gov.di.ipv.core.library.journeys.JourneyUris.JOURNEY_ERROR_PATH;

public class CheckCoiHandler implements RequestHandler<ProcessRequest, Map<String, Object>> {
    private static final Logger LOGGER = LogManager.getLogger();
    private static final JourneyResponse JOURNEY_COI_CHECK_PASSED =
            new JourneyResponse(JOURNEY_COI_CHECK_PASSED_PATH);
    private static final JourneyResponse JOURNEY_COI_CHECK_FAILED =
            new JourneyResponse(JOURNEY_COI_CHECK_FAILED_PATH);

    private final ConfigService configService;
    private final AuditService auditService;
    private final IpvSessionService ipvSessionService;
    private final ClientOAuthSessionDetailsService clientOAuthSessionDetailsService;
    private final SessionCredentialsService sessionCredentialsService;
    private final UserIdentityService userIdentityService;
    private final EvcsService evcsService;

    @SuppressWarnings({"java:S107"}) // Methods should not have too many parameters
    public CheckCoiHandler(
            ConfigService configService,
            AuditService auditService,
            IpvSessionService ipvSessionService,
            ClientOAuthSessionDetailsService clientOAuthSessionDetailsService,
            SessionCredentialsService sessionCredentialsService,
            UserIdentityService userIdentityService,
            EvcsService evcsService) {
        this.configService = configService;
        this.auditService = auditService;
        this.ipvSessionService = ipvSessionService;
        this.clientOAuthSessionDetailsService = clientOAuthSessionDetailsService;
        this.sessionCredentialsService = sessionCredentialsService;
        this.userIdentityService = userIdentityService;
        this.evcsService = evcsService;
    }

    @ExcludeFromGeneratedCoverageReport
    public CheckCoiHandler() {
        this(ConfigService.create());
    }

    @ExcludeFromGeneratedCoverageReport
    public CheckCoiHandler(ConfigService configService) {
        this.configService = configService;
        this.auditService = AuditService.create(configService);
        this.ipvSessionService = new IpvSessionService(configService);
        this.clientOAuthSessionDetailsService = new ClientOAuthSessionDetailsService(configService);
        this.sessionCredentialsService = new SessionCredentialsService(configService);
        this.userIdentityService = new UserIdentityService(configService);
        this.evcsService = new EvcsService(configService);
    }

    @Override
    @Logging(clearState = true)
    @Metrics(captureColdStart = true)
    public Map<String, Object> handleRequest(ProcessRequest request, Context context) {
        configService.setFeatureSet(RequestHelper.getFeatureSet(request));
        LogHelper.attachComponentId(configService);

        try {
            var ipAddress = request.getIpAddress();
            var deviceInformation = request.getDeviceInformation();
            var ipvSessionId = RequestHelper.getIpvSessionId(request);
            var ipvSession = ipvSessionService.getIpvSession(ipvSessionId);
            var clientOAuthSession =
                    clientOAuthSessionDetailsService.getClientOAuthSession(
                            ipvSession.getClientOAuthSessionId());
            var userId = clientOAuthSession.getUserId();
            var govukSigninJourneyId = clientOAuthSession.getGovukSigninJourneyId();
            LogHelper.attachGovukSigninJourneyIdToLogs(govukSigninJourneyId);

            var checkType = getCheckType(clientOAuthSession, request);

            var auditEventUser =
                    new AuditEventUser(userId, ipvSessionId, govukSigninJourneyId, ipAddress);
            sendAuditEvent(
                    AuditEventTypes.IPV_CONTINUITY_OF_IDENTITY_CHECK_START,
                    checkType,
                    null,
                    auditEventUser,
                    null,
                    null,
                    deviceInformation);

            var oldVcs =
                    evcsService.getVerifiableCredentials(
                            userId, clientOAuthSession.getEvcsAccessToken(), CURRENT);
            var sessionVcs = sessionCredentialsService.getCredentials(ipvSessionId, userId);
            var combinedCredentials = Stream.concat(oldVcs.stream(), sessionVcs.stream()).toList();
            var successfulCheck =
                    switch (checkType) {
                        case STANDARD -> userIdentityService.areNamesAndDobCorrelated(
                                combinedCredentials);
                        case REVERIFICATION -> userIdentityService
                                .areNamesAndDobCorrelatedForReverification(combinedCredentials);
                        case ACCOUNT_INTERVENTION -> userIdentityService.areVcsCorrelated(
                                combinedCredentials);
                    };

            sendAuditEvent(
                    AuditEventTypes.IPV_CONTINUITY_OF_IDENTITY_CHECK_END,
                    checkType,
                    successfulCheck,
                    auditEventUser,
                    oldVcs,
                    sessionVcs,
                    deviceInformation);

            if (clientOAuthSession.isReverification()) {
                setIpvSessionReverificationStatus(
                        ipvSession,
                        successfulCheck
                                ? ReverificationStatus.SUCCESS
                                : ReverificationStatus.FAILED);
                if (!successfulCheck) {
                    ipvSession.setFailureCode(ReverificationFailureCode.IDENTITY_DID_NOT_MATCH);
                    ipvSessionService.updateIpvSession(ipvSession);
                }
            }

            if (!successfulCheck) {
                LOGGER.info(
                        LogHelper.buildLogMessage("Failed COI check")
                                .with(LOG_CHECK_TYPE.getFieldName(), checkType));
                return JOURNEY_COI_CHECK_FAILED.toObjectMap();
            }

            LOGGER.info(
                    LogHelper.buildLogMessage("Successful COI check")
                            .with(LOG_CHECK_TYPE.getFieldName(), checkType));

            return JOURNEY_COI_CHECK_PASSED.toObjectMap();

        } catch (HttpResponseExceptionWithErrorBody
                | EvcsServiceException
                | VerifiableCredentialException e) {
            var errorMessage = LogHelper.buildErrorMessage("Received exception", e);
            if (ErrorResponse.FAILED_NAME_CORRELATION.equals(e.getErrorResponse())) {
                LOGGER.info(errorMessage);
            } else {
                LOGGER.error(errorMessage);
            }
            return new JourneyErrorResponse(
                            JOURNEY_ERROR_PATH, e.getResponseCode(), e.getErrorResponse())
                    .toObjectMap();
        } catch (CredentialParseException e) {
            LOGGER.error(LogHelper.buildErrorMessage("Unable to parse existing credentials", e));
            return new JourneyErrorResponse(
                            JOURNEY_ERROR_PATH,
                            HttpStatusCode.INTERNAL_SERVER_ERROR,
                            FAILED_TO_PARSE_ISSUED_CREDENTIALS)
                    .toObjectMap();
        } catch (UnknownCoiCheckTypeException e) {
            LOGGER.error(
                    LogHelper.buildErrorMessage("Unknown COI check type received", e)
                            .with(LOG_CHECK_TYPE.getFieldName(), e.getCheckType()));
            return new JourneyErrorResponse(
                            JOURNEY_ERROR_PATH,
                            HttpStatusCode.INTERNAL_SERVER_ERROR,
                            UNKNOWN_CHECK_TYPE)
                    .toObjectMap();
        } catch (IpvSessionNotFoundException e) {
            LOGGER.error(LogHelper.buildErrorMessage("Failed to find ipv session", e));
            return new JourneyErrorResponse(
                            JOURNEY_ERROR_PATH,
                            HttpStatusCode.INTERNAL_SERVER_ERROR,
                            IPV_SESSION_NOT_FOUND)
                    .toObjectMap();
        } catch (Exception e) {
            LOGGER.error(LogHelper.buildErrorMessage("Unhandled lambda exception", e));
            throw e;
        } finally {
            auditService.awaitAuditEvents();
        }
    }

    private void setIpvSessionReverificationStatus(
            IpvSessionItem ipvSessionItem, ReverificationStatus status) {
        ipvSessionItem.setReverificationStatus(status);
        ipvSessionService.updateIpvSession(ipvSessionItem);
    }

    private void sendAuditEvent(
            AuditEventTypes auditEventType,
            CoiCheckType coiCheckType,
            Boolean coiCheckSuccess,
            AuditEventUser auditEventUser,
            List<VerifiableCredential> oldVcs,
            List<VerifiableCredential> sessionsVcs,
            String deviceInformation)
            throws HttpResponseExceptionWithErrorBody, CredentialParseException {

        var restrictedData =
                auditEventType == AuditEventTypes.IPV_CONTINUITY_OF_IDENTITY_CHECK_END
                        ? getRestrictedCheckCoiAuditData(oldVcs, sessionsVcs, deviceInformation)
                        : new AuditRestrictedDeviceInformation(deviceInformation);

        auditService.sendAuditEvent(
                AuditEvent.createWithDeviceInformation(
                        auditEventType,
                        configService.getParameter(ConfigurationVariable.COMPONENT_ID),
                        auditEventUser,
                        new AuditExtensionCoiCheck(coiCheckType, coiCheckSuccess),
                        restrictedData));
    }

    private AuditRestrictedCheckCoi getRestrictedCheckCoiAuditData(
            List<VerifiableCredential> oldVcs,
            List<VerifiableCredential> sessionVcs,
            String deviceInformation)
            throws HttpResponseExceptionWithErrorBody, CredentialParseException {

        var oldIdentityClaim = userIdentityService.findIdentityClaim(oldVcs);
        var sessionIdentityClaim = userIdentityService.findIdentityClaim(sessionVcs);

        Optional<List<PostalAddress>> oldAddressClaim = userIdentityService.getAddressClaim(oldVcs);
        Optional<List<PostalAddress>> sessionAddressClaim =
                userIdentityService.getAddressClaim(sessionVcs);

        return new AuditRestrictedCheckCoi(
                oldIdentityClaim.map(IdentityClaim::getName).orElse(null),
                sessionIdentityClaim.map(IdentityClaim::getName).orElse(null),
                oldIdentityClaim.map(IdentityClaim::getBirthDate).orElse(null),
                sessionIdentityClaim.map(IdentityClaim::getBirthDate).orElse(null),
                oldAddressClaim.orElse(null),
                sessionAddressClaim.orElse(null),
                new DeviceInformation(deviceInformation));
    }

    private CoiCheckType getCheckType(
            ClientOAuthSessionItem clientOAuthSession, ProcessRequest request)
            throws HttpResponseExceptionWithErrorBody, UnknownCoiCheckTypeException {
        if (TRUE.equals(clientOAuthSession.getReproveIdentity())) {
            LOGGER.info(
                    LogHelper.buildLogMessage(
                            "Reprove identity flag set - checking full name and DOB"));
            return CoiCheckType.ACCOUNT_INTERVENTION;
        }
        return RequestHelper.getCoiCheckType(request);
    }
}
