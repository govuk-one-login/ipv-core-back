package uk.gov.di.ipv.core.storeidentity;

import com.amazonaws.services.lambda.runtime.Context;
import com.amazonaws.services.lambda.runtime.RequestHandler;
import com.amazonaws.services.lambda.runtime.events.APIGatewayProxyRequestEvent;
import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.apache.http.HttpStatus;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import software.amazon.lambda.powertools.logging.Logging;
import software.amazon.lambda.powertools.tracing.Tracing;
import uk.gov.di.ipv.core.library.annotations.ExcludeFromGeneratedCoverageReport;
import uk.gov.di.ipv.core.library.auditing.AuditEvent;
import uk.gov.di.ipv.core.library.auditing.AuditEventUser;
import uk.gov.di.ipv.core.library.auditing.extension.AuditExtensionIdentityType;
import uk.gov.di.ipv.core.library.auditing.restricted.AuditRestrictedDeviceInformation;
import uk.gov.di.ipv.core.library.config.ConfigurationVariable;
import uk.gov.di.ipv.core.library.domain.ErrorResponse;
import uk.gov.di.ipv.core.library.domain.JourneyErrorResponse;
import uk.gov.di.ipv.core.library.domain.JourneyResponse;
import uk.gov.di.ipv.core.library.domain.ProcessRequest;
import uk.gov.di.ipv.core.library.domain.VerifiableCredential;
import uk.gov.di.ipv.core.library.enums.IdentityType;
import uk.gov.di.ipv.core.library.enums.Vot;
import uk.gov.di.ipv.core.library.exception.EvcsServiceException;
import uk.gov.di.ipv.core.library.exceptions.HttpResponseExceptionWithErrorBody;
import uk.gov.di.ipv.core.library.exceptions.IpvSessionNotFoundException;
import uk.gov.di.ipv.core.library.exceptions.VerifiableCredentialException;
import uk.gov.di.ipv.core.library.helpers.LogHelper;
import uk.gov.di.ipv.core.library.helpers.RequestHelper;
import uk.gov.di.ipv.core.library.helpers.StepFunctionHelpers;
import uk.gov.di.ipv.core.library.persistence.item.ClientOAuthSessionItem;
import uk.gov.di.ipv.core.library.persistence.item.IpvSessionItem;
import uk.gov.di.ipv.core.library.service.AuditService;
import uk.gov.di.ipv.core.library.service.ClientOAuthSessionDetailsService;
import uk.gov.di.ipv.core.library.service.ConfigService;
import uk.gov.di.ipv.core.library.service.EvcsService;
import uk.gov.di.ipv.core.library.service.IpvSessionService;
import uk.gov.di.ipv.core.library.verifiablecredential.service.SessionCredentialsService;
import uk.gov.di.ipv.core.library.verifiablecredential.service.VerifiableCredentialService;

import java.time.Instant;
import java.util.List;
import java.util.Map;

import static org.apache.http.HttpStatus.SC_INTERNAL_SERVER_ERROR;
import static uk.gov.di.ipv.core.library.auditing.AuditEventTypes.IPV_IDENTITY_STORED;
import static uk.gov.di.ipv.core.library.config.CoreFeatureFlag.EVCS_READ_ENABLED;
import static uk.gov.di.ipv.core.library.config.CoreFeatureFlag.EVCS_WRITE_ENABLED;
import static uk.gov.di.ipv.core.library.domain.ErrorResponse.IPV_SESSION_NOT_FOUND;
import static uk.gov.di.ipv.core.library.enums.Vot.P0;
import static uk.gov.di.ipv.core.library.journeys.JourneyUris.JOURNEY_ERROR_PATH;
import static uk.gov.di.ipv.core.library.journeys.JourneyUris.JOURNEY_IDENTITY_STORED_PATH;

public class StoreIdentityHandler
        implements RequestHandler<APIGatewayProxyRequestEvent, Map<String, Object>> {
    private static final Logger LOGGER = LogManager.getLogger();
    private static final ObjectMapper OBJECT_MAPPER = new ObjectMapper();
    private static final Map<String, Object> JOURNEY_IDENTITY_STORED =
            new JourneyResponse(JOURNEY_IDENTITY_STORED_PATH).toObjectMap();
    private final ConfigService configService;
    private final IpvSessionService ipvSessionService;
    private final ClientOAuthSessionDetailsService clientOAuthSessionDetailsService;
    private final SessionCredentialsService sessionCredentialsService;
    private final VerifiableCredentialService verifiableCredentialService;
    private final AuditService auditService;
    private final EvcsService evcsService;

    public StoreIdentityHandler(
            ConfigService configService,
            ClientOAuthSessionDetailsService clientOAuthSessionDetailsService,
            IpvSessionService ipvSessionService,
            SessionCredentialsService sessionCredentialsService,
            VerifiableCredentialService verifiableCredentialService,
            AuditService auditService,
            EvcsService evcsService) {
        this.configService = configService;
        this.clientOAuthSessionDetailsService = clientOAuthSessionDetailsService;
        this.ipvSessionService = ipvSessionService;
        this.sessionCredentialsService = sessionCredentialsService;
        this.verifiableCredentialService = verifiableCredentialService;
        this.auditService = auditService;
        this.evcsService = evcsService;
    }

    @ExcludeFromGeneratedCoverageReport
    public StoreIdentityHandler() {
        this(ConfigService.create());
    }

    @ExcludeFromGeneratedCoverageReport
    public StoreIdentityHandler(ConfigService configService) {
        this.configService = configService;
        this.ipvSessionService = new IpvSessionService(configService);
        this.clientOAuthSessionDetailsService = new ClientOAuthSessionDetailsService(configService);
        this.sessionCredentialsService = new SessionCredentialsService(configService);
        this.verifiableCredentialService = new VerifiableCredentialService(configService);
        this.auditService = AuditService.create(configService);
        this.evcsService = new EvcsService(configService);
    }

    @Override
    @Tracing
    @Logging(clearState = true)
    public Map<String, Object> handleRequest(
            APIGatewayProxyRequestEvent proxyRequest, Context context) {
        LogHelper.attachComponentId(configService);

        try {
            var processRequest =
                    OBJECT_MAPPER.readValue(proxyRequest.getBody(), ProcessRequest.class);
            configService.setFeatureSet(RequestHelper.getFeatureSet(processRequest));

            var ipvSessionItem =
                    ipvSessionService.getIpvSession(RequestHelper.getIpvSessionId(processRequest));
            var clientOAuthSessionItem =
                    clientOAuthSessionDetailsService.getClientOAuthSession(
                            ipvSessionItem.getClientOAuthSessionId());
            LogHelper.attachGovukSigninJourneyIdToLogs(
                    clientOAuthSessionItem.getGovukSigninJourneyId());

            var identityType = RequestHelper.getIdentityType(processRequest);
            var ipAddress = RequestHelper.getIpAddress(processRequest);

            storeIdentity(ipvSessionItem, clientOAuthSessionItem, identityType);
            sendIdentityStoredEvent(
                    ipvSessionItem,
                    clientOAuthSessionItem,
                    identityType,
                    ipAddress,
                    processRequest.getDeviceInformation());

            return JOURNEY_IDENTITY_STORED;

        } catch (HttpResponseExceptionWithErrorBody
                | VerifiableCredentialException
                | EvcsServiceException e) {
            LOGGER.error(LogHelper.buildErrorMessage("Failed to store identity", e));
            return new JourneyErrorResponse(
                            JOURNEY_ERROR_PATH, e.getResponseCode(), e.getErrorResponse())
                    .toObjectMap();
        } catch (IpvSessionNotFoundException e) {
            LOGGER.error(LogHelper.buildErrorMessage("Failed to find ipv session", e));
            return new JourneyErrorResponse(
                            JOURNEY_ERROR_PATH,
                            HttpStatus.SC_INTERNAL_SERVER_ERROR,
                            IPV_SESSION_NOT_FOUND)
                    .toObjectMap();
        } catch (JsonProcessingException e) {
            LOGGER.error(LogHelper.buildErrorMessage("Failed to create journey request", e));
            return StepFunctionHelpers.generateErrorOutputMap(
                    SC_INTERNAL_SERVER_ERROR, ErrorResponse.FAILED_TO_PARSE_JSON_MESSAGE);

        } catch (Exception e) {
            LOGGER.error(LogHelper.buildErrorMessage("Unhandled lambda exception", e));
            throw e;
        } finally {
            auditService.awaitAuditEvents();
        }
    }

    private void storeIdentity(
            IpvSessionItem ipvSessionItem,
            ClientOAuthSessionItem clientOAuthSessionItem,
            IdentityType identityType)
            throws VerifiableCredentialException, EvcsServiceException {
        String userId = clientOAuthSessionItem.getUserId();
        List<VerifiableCredential> credentials =
                sessionCredentialsService.getCredentials(ipvSessionItem.getIpvSessionId(), userId);

        if (configService.enabled(EVCS_WRITE_ENABLED)) {
            try {
                if (identityType != IdentityType.PENDING) {
                    evcsService.storeCompletedIdentity(
                            userId, credentials, clientOAuthSessionItem.getEvcsAccessToken());
                } else {
                    evcsService.storePendingIdentity(
                            userId, credentials, clientOAuthSessionItem.getEvcsAccessToken());
                }
                credentials.forEach(credential -> credential.setMigrated(Instant.now()));
            } catch (EvcsServiceException e) {
                if (configService.enabled(EVCS_READ_ENABLED)) {
                    throw e;
                } else {
                    LOGGER.error(LogHelper.buildErrorMessage("Failed to store EVCS identity", e));
                }
            }
        }

        verifiableCredentialService.storeIdentity(credentials, userId);

        LOGGER.info(LogHelper.buildLogMessage("Identity successfully stored"));
    }

    private void sendIdentityStoredEvent(
            IpvSessionItem ipvSessionItem,
            ClientOAuthSessionItem clientOAuthSessionItem,
            IdentityType identityType,
            String ipAddress,
            String deviceInformation) {
        Vot vot = ipvSessionItem.getVot();
        auditService.sendAuditEvent(
                AuditEvent.createWithDeviceInformation(
                        IPV_IDENTITY_STORED,
                        configService.getParameter(ConfigurationVariable.COMPONENT_ID),
                        new AuditEventUser(
                                clientOAuthSessionItem.getUserId(),
                                ipvSessionItem.getIpvSessionId(),
                                clientOAuthSessionItem.getGovukSigninJourneyId(),
                                ipAddress),
                        new AuditExtensionIdentityType(identityType, vot.equals(P0) ? null : vot),
                        new AuditRestrictedDeviceInformation(deviceInformation)));
    }
}
