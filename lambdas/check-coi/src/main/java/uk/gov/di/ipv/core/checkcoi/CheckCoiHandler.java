package uk.gov.di.ipv.core.checkcoi;

import com.amazonaws.services.lambda.runtime.Context;
import com.amazonaws.services.lambda.runtime.RequestHandler;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import software.amazon.lambda.powertools.logging.Logging;
import software.amazon.lambda.powertools.tracing.Tracing;
import uk.gov.di.ipv.core.library.annotations.ExcludeFromGeneratedCoverageReport;
import uk.gov.di.ipv.core.library.auditing.AuditEvent;
import uk.gov.di.ipv.core.library.auditing.AuditEventTypes;
import uk.gov.di.ipv.core.library.auditing.AuditEventUser;
import uk.gov.di.ipv.core.library.auditing.extension.AuditExtensionCoiCheck;
import uk.gov.di.ipv.core.library.auditing.restricted.AuditRestrictedCheckCoi;
import uk.gov.di.ipv.core.library.auditing.restricted.AuditRestrictedDeviceInformation;
import uk.gov.di.ipv.core.library.auditing.restricted.DeviceInformation;
import uk.gov.di.ipv.core.library.config.ConfigurationVariable;
import uk.gov.di.ipv.core.library.domain.JourneyErrorResponse;
import uk.gov.di.ipv.core.library.domain.JourneyResponse;
import uk.gov.di.ipv.core.library.domain.ProcessRequest;
import uk.gov.di.ipv.core.library.domain.ReverificationStatus;
import uk.gov.di.ipv.core.library.domain.ScopeConstants;
import uk.gov.di.ipv.core.library.domain.VerifiableCredential;
import uk.gov.di.ipv.core.library.enums.CoiCheckType;
import uk.gov.di.ipv.core.library.exceptions.CredentialParseException;
import uk.gov.di.ipv.core.library.exceptions.HttpResponseExceptionWithErrorBody;
import uk.gov.di.ipv.core.library.exceptions.SqsException;
import uk.gov.di.ipv.core.library.exceptions.UnknownCoiCheckTypeException;
import uk.gov.di.ipv.core.library.exceptions.VerifiableCredentialException;
import uk.gov.di.ipv.core.library.helpers.LogHelper;
import uk.gov.di.ipv.core.library.helpers.RequestHelper;
import uk.gov.di.ipv.core.library.persistence.item.IpvSessionItem;
import uk.gov.di.ipv.core.library.service.AuditService;
import uk.gov.di.ipv.core.library.service.ClientOAuthSessionDetailsService;
import uk.gov.di.ipv.core.library.service.ConfigService;
import uk.gov.di.ipv.core.library.service.IpvSessionService;
import uk.gov.di.ipv.core.library.service.UserIdentityService;
import uk.gov.di.ipv.core.library.verifiablecredential.service.SessionCredentialsService;
import uk.gov.di.ipv.core.library.verifiablecredential.service.VerifiableCredentialService;

import java.util.List;
import java.util.Map;
import java.util.stream.Stream;

import static com.nimbusds.oauth2.sdk.http.HTTPResponse.SC_SERVER_ERROR;
import static org.apache.http.HttpStatus.SC_INTERNAL_SERVER_ERROR;
import static uk.gov.di.ipv.core.library.domain.ErrorResponse.FAILED_TO_PARSE_ISSUED_CREDENTIALS;
import static uk.gov.di.ipv.core.library.domain.ErrorResponse.FAILED_TO_SEND_AUDIT_EVENT;
import static uk.gov.di.ipv.core.library.domain.ErrorResponse.UNKNOWN_CHECK_TYPE;
import static uk.gov.di.ipv.core.library.helpers.LogHelper.LogField.LOG_CHECK_TYPE;
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
    private final AuditService auditService;
    private final IpvSessionService ipvSessionService;
    private final ClientOAuthSessionDetailsService clientOAuthSessionDetailsService;
    private final VerifiableCredentialService verifiableCredentialService;
    private final SessionCredentialsService sessionCredentialsService;
    private final UserIdentityService userIdentityService;

    public CheckCoiHandler(
            ConfigService configService,
            AuditService auditService,
            IpvSessionService ipvSessionService,
            ClientOAuthSessionDetailsService clientOAuthSessionDetailsService,
            VerifiableCredentialService verifiableCredentialService,
            SessionCredentialsService sessionCredentialsService,
            UserIdentityService userIdentityService) {
        this.configService = configService;
        this.auditService = auditService;
        this.ipvSessionService = ipvSessionService;
        this.clientOAuthSessionDetailsService = clientOAuthSessionDetailsService;
        this.verifiableCredentialService = verifiableCredentialService;
        this.sessionCredentialsService = sessionCredentialsService;
        this.userIdentityService = userIdentityService;
    }

    @ExcludeFromGeneratedCoverageReport
    public CheckCoiHandler() {
        this.configService = new ConfigService();
        this.auditService = new AuditService(AuditService.getSqsClient(), configService);
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
            var ipAddress = request.getIpAddress();
            var deviceInformation = request.getDeviceInformation();
            var ipvSession =
                    ipvSessionService.getIpvSession(RequestHelper.getIpvSessionId(request));
            var ipvSessionId = ipvSession.getIpvSessionId();

            var clientOAuthSession =
                    clientOAuthSessionDetailsService.getClientOAuthSession(
                            ipvSession.getClientOAuthSessionId());
            var userId = clientOAuthSession.getUserId();
            var govukSigninJourneyId = clientOAuthSession.getGovukSigninJourneyId();
            LogHelper.attachGovukSigninJourneyIdToLogs(govukSigninJourneyId);

            var checkType = RequestHelper.getCoiCheckType(request);
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

            var oldVcs = verifiableCredentialService.getVcs(userId);
            var sessionVcs = sessionCredentialsService.getCredentials(ipvSessionId, userId);

            var combinedCredentials = Stream.concat(oldVcs.stream(), sessionVcs.stream()).toList();

            var successfulCheck =
                    switch (checkType) {
                        case GIVEN_NAMES_AND_DOB -> userIdentityService
                                .areGivenNamesAndDobCorrelated(combinedCredentials);
                        case FAMILY_NAME_AND_DOB -> userIdentityService
                                .areFamilyNameAndDobCorrelatedForCoiCheck(combinedCredentials);
                        case FULL_NAME_AND_DOB -> userIdentityService.areVcsCorrelated(
                                combinedCredentials);
                    };

            var scopeClaims = clientOAuthSession.getScopeClaims();
            var isReverification = scopeClaims.contains(ScopeConstants.REVERIFICATION);

            sendAuditEvent(
                    AuditEventTypes.IPV_CONTINUITY_OF_IDENTITY_CHECK_END,
                    checkType,
                    successfulCheck,
                    auditEventUser,
                    oldVcs,
                    sessionVcs,
                    deviceInformation);

            if (isReverification) {
                setIpvSessionReverificationStatus(
                        ipvSession,
                        successfulCheck
                                ? ReverificationStatus.SUCCESS
                                : ReverificationStatus.FAILED);
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
        } catch (SqsException e) {
            LOGGER.error(LogHelper.buildErrorMessage("Failed to send audit event", e));
            return new JourneyErrorResponse(
                            JOURNEY_ERROR_PATH, SC_SERVER_ERROR, FAILED_TO_SEND_AUDIT_EVENT)
                    .toObjectMap();
        } catch (UnknownCoiCheckTypeException e) {
            LOGGER.error(
                    LogHelper.buildErrorMessage("Unknown COI check type received", e)
                            .with(LOG_CHECK_TYPE.getFieldName(), e.getCheckType()));
            return new JourneyErrorResponse(
                            JOURNEY_ERROR_PATH, SC_INTERNAL_SERVER_ERROR, UNKNOWN_CHECK_TYPE)
                    .toObjectMap();
        }
    }

    private void setIpvSessionReverificationStatus(
            IpvSessionItem ipvSessionItem, ReverificationStatus status) {
        ipvSessionItem.setReverificationStatus(status);
        ipvSessionService.updateIpvSession(ipvSessionItem);
    }

    @Tracing
    private void sendAuditEvent(
            AuditEventTypes auditEventType,
            CoiCheckType coiCheckType,
            Boolean coiCheckSuccess,
            AuditEventUser auditEventUser,
            List<VerifiableCredential> oldVcs,
            List<VerifiableCredential> sessionsVcs,
            String deviceInformation)
            throws SqsException, HttpResponseExceptionWithErrorBody, CredentialParseException,
                    VerifiableCredentialException {

        var restrictedData =
                auditEventType == AuditEventTypes.IPV_CONTINUITY_OF_IDENTITY_CHECK_END
                        ? getRestrictedCheckCoiAuditData(oldVcs, sessionsVcs, deviceInformation)
                        : new AuditRestrictedDeviceInformation(deviceInformation);

        auditService.sendAuditEvent(
                new AuditEvent(
                        auditEventType,
                        configService.getSsmParameter(ConfigurationVariable.COMPONENT_ID),
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

        if (oldIdentityClaim.isEmpty() || sessionIdentityClaim.isEmpty()) {
            LOGGER.error(LogHelper.buildLogMessage("Failed to get identity claim."));
            return new AuditRestrictedCheckCoi(
                    null, null, null, null, new DeviceInformation(deviceInformation));
        }

        return new AuditRestrictedCheckCoi(
                oldIdentityClaim.get().getName(),
                sessionIdentityClaim.get().getName(),
                oldIdentityClaim.get().getBirthDate(),
                sessionIdentityClaim.get().getBirthDate(),
                new DeviceInformation(deviceInformation));
    }
}
