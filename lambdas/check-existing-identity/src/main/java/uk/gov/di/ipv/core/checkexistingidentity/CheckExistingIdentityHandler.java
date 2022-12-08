package uk.gov.di.ipv.core.checkexistingidentity;

import com.amazonaws.services.lambda.runtime.Context;
import com.amazonaws.services.lambda.runtime.RequestHandler;
import com.amazonaws.services.lambda.runtime.events.APIGatewayProxyRequestEvent;
import com.amazonaws.services.lambda.runtime.events.APIGatewayProxyResponseEvent;
import com.nimbusds.jwt.SignedJWT;
import org.apache.http.HttpStatus;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.apache.logging.log4j.message.StringMapMessage;
import software.amazon.lambda.powertools.logging.Logging;
import software.amazon.lambda.powertools.tracing.Tracing;
import uk.gov.di.ipv.core.library.annotations.ExcludeFromGeneratedCoverageReport;
import uk.gov.di.ipv.core.library.auditing.AuditEvent;
import uk.gov.di.ipv.core.library.auditing.AuditEventTypes;
import uk.gov.di.ipv.core.library.auditing.AuditEventUser;
import uk.gov.di.ipv.core.library.config.ConfigurationVariable;
import uk.gov.di.ipv.core.library.domain.ContraIndicatorItem;
import uk.gov.di.ipv.core.library.domain.ErrorResponse;
import uk.gov.di.ipv.core.library.domain.JourneyResponse;
import uk.gov.di.ipv.core.library.domain.gpg45.Gpg45Profile;
import uk.gov.di.ipv.core.library.domain.gpg45.Gpg45ProfileEvaluator;
import uk.gov.di.ipv.core.library.domain.gpg45.Gpg45Scores;
import uk.gov.di.ipv.core.library.domain.gpg45.exception.UnknownEvidenceTypeException;
import uk.gov.di.ipv.core.library.dto.ClientSessionDetailsDto;
import uk.gov.di.ipv.core.library.dto.CredentialIssuerConfig;
import uk.gov.di.ipv.core.library.dto.VcStatusDto;
import uk.gov.di.ipv.core.library.exceptions.CiRetrievalException;
import uk.gov.di.ipv.core.library.exceptions.HttpResponseExceptionWithErrorBody;
import uk.gov.di.ipv.core.library.exceptions.SqsException;
import uk.gov.di.ipv.core.library.helpers.ApiGatewayResponseGenerator;
import uk.gov.di.ipv.core.library.helpers.LogHelper;
import uk.gov.di.ipv.core.library.helpers.RequestHelper;
import uk.gov.di.ipv.core.library.helpers.VcHelper;
import uk.gov.di.ipv.core.library.persistence.item.IpvSessionItem;
import uk.gov.di.ipv.core.library.service.AuditService;
import uk.gov.di.ipv.core.library.service.CiStorageService;
import uk.gov.di.ipv.core.library.service.ConfigurationService;
import uk.gov.di.ipv.core.library.service.IpvSessionService;
import uk.gov.di.ipv.core.library.service.UserIdentityService;

import java.text.ParseException;
import java.util.ArrayList;
import java.util.List;
import java.util.Optional;

import static uk.gov.di.ipv.core.library.config.ConfigurationVariable.ADDRESS_CRI_ID;

public class CheckExistingIdentityHandler
        implements RequestHandler<APIGatewayProxyRequestEvent, APIGatewayProxyResponseEvent> {
    private static final List<Gpg45Profile> ACCEPTED_PROFILES =
            List.of(Gpg45Profile.M1A, Gpg45Profile.M1B);
    private static final JourneyResponse JOURNEY_REUSE = new JourneyResponse("/journey/reuse");
    private static final JourneyResponse JOURNEY_NEXT = new JourneyResponse("/journey/next");
    private static final String VOT_P2 = "P2";
    private static final Logger LOGGER = LogManager.getLogger();
    private final ConfigurationService configurationService;
    private final UserIdentityService userIdentityService;
    private final IpvSessionService ipvSessionService;
    private final Gpg45ProfileEvaluator gpg45ProfileEvaluator;
    private final CiStorageService ciStorageService;
    private final AuditService auditService;
    private final String componentId;

    public CheckExistingIdentityHandler(
            ConfigurationService configurationService,
            UserIdentityService userIdentityService,
            IpvSessionService ipvSessionService,
            Gpg45ProfileEvaluator gpg45ProfileEvaluator,
            CiStorageService ciStorageService,
            AuditService auditService) {
        this.configurationService = configurationService;
        this.userIdentityService = userIdentityService;
        this.ipvSessionService = ipvSessionService;
        this.gpg45ProfileEvaluator = gpg45ProfileEvaluator;
        this.ciStorageService = ciStorageService;
        this.auditService = auditService;
        this.componentId =
                configurationService.getSsmParameter(ConfigurationVariable.AUDIENCE_FOR_CLIENTS);
    }

    @ExcludeFromGeneratedCoverageReport
    public CheckExistingIdentityHandler() {
        this.configurationService = new ConfigurationService();
        this.userIdentityService = new UserIdentityService(configurationService);
        this.ipvSessionService = new IpvSessionService(configurationService);
        this.gpg45ProfileEvaluator = new Gpg45ProfileEvaluator(configurationService);
        this.ciStorageService = new CiStorageService(configurationService);
        this.auditService =
                new AuditService(AuditService.getDefaultSqsClient(), configurationService);
        componentId =
                configurationService.getSsmParameter(ConfigurationVariable.AUDIENCE_FOR_CLIENTS);
    }

    @Override
    @Tracing
    @Logging(clearState = true)
    public APIGatewayProxyResponseEvent handleRequest(
            APIGatewayProxyRequestEvent event, Context context) {
        LogHelper.attachComponentIdToLogs();

        try {
            String ipvSessionId = RequestHelper.getIpvSessionId(event);
            String ipAddress = RequestHelper.getIpAddress(event);
            IpvSessionItem ipvSessionItem = ipvSessionService.getIpvSession(ipvSessionId);
            ClientSessionDetailsDto clientSessionDetailsDto =
                    ipvSessionItem.getClientSessionDetails();
            String userId = clientSessionDetailsDto.getUserId();

            String govukSigninJourneyId = clientSessionDetailsDto.getGovukSigninJourneyId();
            LogHelper.attachGovukSigninJourneyIdToLogs(govukSigninJourneyId);

            AuditEventUser auditEventUser =
                    new AuditEventUser(userId, ipvSessionId, govukSigninJourneyId, ipAddress);

            userIdentityService.deleteVcStoreItemsIfAnyExpired(userId);

            List<SignedJWT> credentials =
                    gpg45ProfileEvaluator.parseCredentials(
                            userIdentityService.getUserIssuedCredentials(userId));

            List<ContraIndicatorItem> ciItems;
            ciItems =
                    ciStorageService.getCIs(
                            clientSessionDetailsDto.getUserId(),
                            clientSessionDetailsDto.getGovukSigninJourneyId(),
                            ipAddress);

            Optional<JourneyResponse> contraIndicatorErrorJourneyResponse =
                    gpg45ProfileEvaluator.getJourneyResponseForStoredCis(ciItems);
            if (contraIndicatorErrorJourneyResponse.isEmpty()) {
                Gpg45Scores gpg45Scores = gpg45ProfileEvaluator.buildScore(credentials);
                Optional<Gpg45Profile> matchedProfile =
                        gpg45ProfileEvaluator.getFirstMatchingProfile(
                                gpg45Scores, ACCEPTED_PROFILES);
                if (matchedProfile.isPresent()) {
                    var message =
                            new StringMapMessage()
                                    .with(
                                            "message",
                                            "Matched profile and within CI threshold so returning reuse journey")
                                    .with("profile", matchedProfile.get().getLabel());
                    LOGGER.info(message);

                    auditService.sendAuditEvent(
                            new AuditEvent(
                                    AuditEventTypes.IPV_IDENTITY_REUSE_COMPLETE,
                                    componentId,
                                    auditEventUser));

                    ipvSessionItem.setVot(VOT_P2);

                    updateSuccessfulVcStatuses(ipvSessionItem, credentials);

                    return ApiGatewayResponseGenerator.proxyJsonResponse(
                            HttpStatus.SC_OK, JOURNEY_REUSE);
                }
            }

            var message =
                    new StringMapMessage()
                            .with(
                                    "message",
                                    "Failed to match profile so clearing VCs and returning next");
            LOGGER.info(message);

            if (!credentials.isEmpty()) {
                auditService.sendAuditEvent(
                        new AuditEvent(
                                AuditEventTypes.IPV_IDENTITY_REUSE_RESET,
                                componentId,
                                auditEventUser));

                userIdentityService.deleteVcStoreItems(userId);
            }

            return ApiGatewayResponseGenerator.proxyJsonResponse(HttpStatus.SC_OK, JOURNEY_NEXT);
        } catch (HttpResponseExceptionWithErrorBody e) {
            return ApiGatewayResponseGenerator.proxyJsonResponse(
                    e.getResponseCode(), e.getErrorBody());
        } catch (ParseException e) {
            LOGGER.error("Unable to parse existing credentials", e);
            return ApiGatewayResponseGenerator.proxyJsonResponse(
                    HttpStatus.SC_INTERNAL_SERVER_ERROR,
                    ErrorResponse.FAILED_TO_PARSE_ISSUED_CREDENTIALS);
        } catch (CiRetrievalException e) {
            LOGGER.error("Error when fetching CIs from storage system", e);
            return ApiGatewayResponseGenerator.proxyJsonResponse(
                    HttpStatus.SC_INTERNAL_SERVER_ERROR, ErrorResponse.FAILED_TO_GET_STORED_CIS);
        } catch (UnknownEvidenceTypeException e) {
            LOGGER.error("Unable to determine type of credential", e);
            return ApiGatewayResponseGenerator.proxyJsonResponse(
                    HttpStatus.SC_INTERNAL_SERVER_ERROR,
                    ErrorResponse.FAILED_TO_DETERMINE_CREDENTIAL_TYPE);
        } catch (SqsException e) {
            LOGGER.error("Failed to send audit event to SQS queue", e);
            return ApiGatewayResponseGenerator.proxyJsonResponse(
                    HttpStatus.SC_INTERNAL_SERVER_ERROR, ErrorResponse.FAILED_TO_SEND_AUDIT_EVENT);
        }
    }

    @Tracing
    private void updateSuccessfulVcStatuses(
            IpvSessionItem ipvSessionItem, List<SignedJWT> credentials) throws ParseException {

        // get list of success vc's
        List<VcStatusDto> currentVcStatusDtos = ipvSessionItem.getCurrentVcStatuses();

        if (currentVcStatusDtos == null) {
            currentVcStatusDtos = new ArrayList<>();
        }

        if (currentVcStatusDtos.size() != credentials.size()) {
            List<VcStatusDto> updatedStatuses = generateVcSuccessStatuses(credentials);
            ipvSessionItem.setCurrentVcStatuses(updatedStatuses);
            ipvSessionService.updateIpvSession(ipvSessionItem);
        }
    }

    @Tracing
    private List<VcStatusDto> generateVcSuccessStatuses(List<SignedJWT> credentials)
            throws ParseException {
        List<VcStatusDto> vcStatuses = new ArrayList<>();
        String addressCriId = configurationService.getSsmParameter(ADDRESS_CRI_ID);

        for (SignedJWT signedJWT : credentials) {

            CredentialIssuerConfig addressCriConfig =
                    configurationService.getCredentialIssuer(addressCriId);
            boolean isSuccessful = VcHelper.isSuccessfulVcIgnoringCi(signedJWT, addressCriConfig);

            vcStatuses.add(new VcStatusDto(signedJWT.getJWTClaimsSet().getIssuer(), isSuccessful));
        }
        return vcStatuses;
    }
}
