package uk.gov.di.ipv.core.resetidentity;

import com.amazonaws.services.lambda.runtime.Context;
import com.amazonaws.services.lambda.runtime.RequestHandler;
import org.apache.http.HttpStatus;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import software.amazon.lambda.powertools.logging.Logging;
import software.amazon.lambda.powertools.tracing.Tracing;
import uk.gov.di.ipv.core.library.annotations.ExcludeFromGeneratedCoverageReport;
import uk.gov.di.ipv.core.library.auditing.AuditEvent;
import uk.gov.di.ipv.core.library.auditing.AuditEventTypes;
import uk.gov.di.ipv.core.library.auditing.AuditEventUser;
import uk.gov.di.ipv.core.library.config.ConfigurationVariable;
import uk.gov.di.ipv.core.library.domain.ErrorResponse;
import uk.gov.di.ipv.core.library.domain.IdentityClaim;
import uk.gov.di.ipv.core.library.domain.JourneyErrorResponse;
import uk.gov.di.ipv.core.library.domain.JourneyResponse;
import uk.gov.di.ipv.core.library.domain.ProcessRequest;
import uk.gov.di.ipv.core.library.domain.ProfileType;
import uk.gov.di.ipv.core.library.domain.VerifiableCredential;
import uk.gov.di.ipv.core.library.exceptions.CredentialParseException;
import uk.gov.di.ipv.core.library.exceptions.HttpResponseExceptionWithErrorBody;
import uk.gov.di.ipv.core.library.exceptions.SqsException;
import uk.gov.di.ipv.core.library.exceptions.VerifiableCredentialException;
import uk.gov.di.ipv.core.library.helpers.LogHelper;
import uk.gov.di.ipv.core.library.helpers.RequestHelper;
import uk.gov.di.ipv.core.library.persistence.item.ClientOAuthSessionItem;
import uk.gov.di.ipv.core.library.persistence.item.CriResponseItem;
import uk.gov.di.ipv.core.library.persistence.item.IpvSessionItem;
import uk.gov.di.ipv.core.library.service.AuditService;
import uk.gov.di.ipv.core.library.service.ClientOAuthSessionDetailsService;
import uk.gov.di.ipv.core.library.service.ConfigService;
import uk.gov.di.ipv.core.library.service.CriResponseService;
import uk.gov.di.ipv.core.library.service.EmailService;
import uk.gov.di.ipv.core.library.service.EmailServiceFactory;
import uk.gov.di.ipv.core.library.service.IpvSessionService;
import uk.gov.di.ipv.core.library.service.UserIdentityService;
import uk.gov.di.ipv.core.library.verifiablecredential.helpers.VcHelper;
import uk.gov.di.ipv.core.library.verifiablecredential.service.SessionCredentialsService;
import uk.gov.di.ipv.core.library.verifiablecredential.service.VerifiableCredentialService;

import java.util.List;
import java.util.Map;
import java.util.Optional;

import static uk.gov.di.ipv.core.library.domain.CriConstants.F2F_CRI;
import static uk.gov.di.ipv.core.library.domain.ErrorResponse.FAILED_TO_PARSE_ISSUED_CREDENTIALS;
import static uk.gov.di.ipv.core.library.domain.ErrorResponse.FAILED_TO_SEND_AUDIT_EVENT;
import static uk.gov.di.ipv.core.library.helpers.RequestHelper.getIpAddress;
import static uk.gov.di.ipv.core.library.helpers.RequestHelper.getIpvSessionId;
import static uk.gov.di.ipv.core.library.journeyuris.JourneyUris.JOURNEY_ERROR_PATH;
import static uk.gov.di.ipv.core.library.journeyuris.JourneyUris.JOURNEY_NEXT_PATH;

public class ResetIdentityHandler implements RequestHandler<ProcessRequest, Map<String, Object>> {
    private static final Logger LOGGER = LogManager.getLogger();
    private static final Map<String, Object> JOURNEY_NEXT =
            new JourneyResponse(JOURNEY_NEXT_PATH).toObjectMap();
    private final ConfigService configService;
    private final AuditService auditService;
    private final CriResponseService criResponseService;
    private final EmailServiceFactory emailServiceFactory;
    private final IpvSessionService ipvSessionService;
    private final ClientOAuthSessionDetailsService clientOAuthSessionDetailsService;
    private final VerifiableCredentialService verifiableCredentialService;
    private final SessionCredentialsService sessionCredentialsService;
    private final UserIdentityService userIdentityService;

    @SuppressWarnings("unused") // Used through dependency injection
    public ResetIdentityHandler(
            ConfigService configService,
            AuditService auditService,
            IpvSessionService ipvSessionService,
            ClientOAuthSessionDetailsService clientOAuthSessionDetailsService,
            CriResponseService criResponseService,
            VerifiableCredentialService verifiableCredentialService,
            SessionCredentialsService sessionCredentialsService,
            EmailServiceFactory emailServiceFactory,
            UserIdentityService userIdentityService) {
        this.configService = configService;
        this.auditService = auditService;
        this.ipvSessionService = ipvSessionService;
        this.clientOAuthSessionDetailsService = clientOAuthSessionDetailsService;
        this.criResponseService = criResponseService;
        this.verifiableCredentialService = verifiableCredentialService;
        this.sessionCredentialsService = sessionCredentialsService;
        this.emailServiceFactory = emailServiceFactory;
        this.userIdentityService = userIdentityService;
    }

    @SuppressWarnings("unused") // Used by AWS
    @ExcludeFromGeneratedCoverageReport
    public ResetIdentityHandler() {
        this.configService = new ConfigService();
        this.auditService = new AuditService(AuditService.getDefaultSqsClient(), configService);
        this.ipvSessionService = new IpvSessionService(configService);
        this.clientOAuthSessionDetailsService = new ClientOAuthSessionDetailsService(configService);
        this.criResponseService = new CriResponseService(configService);
        this.verifiableCredentialService = new VerifiableCredentialService(configService);
        this.sessionCredentialsService = new SessionCredentialsService(configService);
        this.emailServiceFactory = new EmailServiceFactory(configService);
        this.userIdentityService = new UserIdentityService(configService);
    }

    @Override
    @Tracing
    @Logging(clearState = true)
    public Map<String, Object> handleRequest(ProcessRequest event, Context context) {
        LogHelper.attachComponentId(configService);

        try {
            String ipvSessionId = getIpvSessionId(event);
            boolean isUserInitiated = RequestHelper.getIsUserInitiated(event);
            boolean deleteOnlyGPG45VCs = RequestHelper.getDeleteOnlyGPG45VCs(event);

            configService.setFeatureSet(RequestHelper.getFeatureSet(event));

            IpvSessionItem ipvSessionItem = ipvSessionService.getIpvSession(ipvSessionId);
            ClientOAuthSessionItem clientOAuthSessionItem =
                    clientOAuthSessionDetailsService.getClientOAuthSession(
                            ipvSessionItem.getClientOAuthSessionId());
            String userId = clientOAuthSessionItem.getUserId();
            String govukSigninJourneyId = clientOAuthSessionItem.getGovukSigninJourneyId();
            LogHelper.attachGovukSigninJourneyIdToLogs(govukSigninJourneyId);

            List<VerifiableCredential> vcs =
                    verifiableCredentialService.getVcs(clientOAuthSessionItem.getUserId());

            if (deleteOnlyGPG45VCs) {
                vcs = VcHelper.filterVCBasedOnProfileType(vcs, ProfileType.GPG45);
            }

            // Make sure we do this before deleting the credentials!
            String userName = getUnconfirmedUserName(vcs);

            verifiableCredentialService.deleteVcs(vcs, isUserInitiated);
            criResponseService.deleteCriResponseItem(userId, F2F_CRI);
            sessionCredentialsService.deleteSessionCredentials(ipvSessionItem.getIpvSessionId());

            if (isUserInitiated) {
                sendIpvVcResetAuditEvent(event, userId, govukSigninJourneyId);

                // Create a new email service for each request so that we don't risk using stale
                // configuration.
                final EmailService emailService = emailServiceFactory.getEmailService();

                CriResponseItem f2fRequest = criResponseService.getFaceToFaceRequest(userId);
                if (f2fRequest == null) {
                    emailService.sendUserTriggeredIdentityResetConfirmation(
                            ipvSessionItem.getEmailAddress(), userName);
                } else {
                    emailService.sendUserTriggeredF2FIdentityResetConfirmation(
                            ipvSessionItem.getEmailAddress(), userName);
                }
            }
            return JOURNEY_NEXT;
        } catch (HttpResponseExceptionWithErrorBody | VerifiableCredentialException e) {
            return buildErrorResponse(e.getErrorResponse(), e);
        } catch (CredentialParseException e) {
            return buildErrorResponse(FAILED_TO_PARSE_ISSUED_CREDENTIALS, e);
        } catch (SqsException e) {
            return buildErrorResponse(FAILED_TO_SEND_AUDIT_EVENT, e);
        }
    }

    private Map<String, Object> buildErrorResponse(ErrorResponse errorResponse, Exception e) {
        LOGGER.error(LogHelper.buildErrorMessage(errorResponse.getMessage(), e));
        return new JourneyErrorResponse(
                        JOURNEY_ERROR_PATH, HttpStatus.SC_INTERNAL_SERVER_ERROR, errorResponse)
                .toObjectMap();
    }

    private void sendIpvVcResetAuditEvent(
            ProcessRequest event, String userId, String govukSigninJourneyId)
            throws SqsException, HttpResponseExceptionWithErrorBody {
        auditService.sendAuditEvent(
                new AuditEvent(
                        AuditEventTypes.IPV_CORE_VC_RESET,
                        configService.getSsmParameter(ConfigurationVariable.COMPONENT_ID),
                        new AuditEventUser(
                                userId,
                                getIpvSessionId(event),
                                govukSigninJourneyId,
                                getIpAddress(event))));
    }

    // Try to get the user's name from their VCs. It's not the end of the world if this fails so
    // just return null in that case.
    private String getUnconfirmedUserName(List<VerifiableCredential> vcs) {
        try {
            final Optional<IdentityClaim> identityClaim =
                    userIdentityService.findIdentityClaim(vcs, false);

            if (identityClaim.isEmpty()) {
                LOGGER.warn(LogHelper.buildLogMessage("Failed to find identity claim"));
                return null;
            }

            return identityClaim.get().getFullName();
        } catch (Exception e) {
            LOGGER.error(
                    LogHelper.buildErrorMessage(
                            "Exception caught trying to find user's identity", e));
        }

        return null;
    }
}
