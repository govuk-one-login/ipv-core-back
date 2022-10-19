package uk.gov.di.ipv.core.evaluategpg45scores;

import com.amazonaws.services.lambda.runtime.Context;
import com.amazonaws.services.lambda.runtime.RequestHandler;
import com.amazonaws.services.lambda.runtime.events.APIGatewayProxyRequestEvent;
import com.amazonaws.services.lambda.runtime.events.APIGatewayProxyResponseEvent;
import com.google.gson.Gson;
import com.nimbusds.jose.shaded.json.JSONArray;
import com.nimbusds.jose.shaded.json.JSONObject;
import com.nimbusds.jwt.SignedJWT;
import org.apache.http.HttpStatus;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.apache.logging.log4j.message.MapMessage;
import software.amazon.lambda.powertools.logging.Logging;
import software.amazon.lambda.powertools.tracing.Tracing;
import uk.gov.di.ipv.core.library.auditing.AuditEvent;
import uk.gov.di.ipv.core.library.auditing.AuditEventTypes;
import uk.gov.di.ipv.core.library.auditing.AuditEventUser;
import uk.gov.di.ipv.core.library.auditing.AuditExtensionGpg45ProfileMatched;
import uk.gov.di.ipv.core.library.config.ConfigurationVariable;
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
import static uk.gov.di.ipv.core.library.domain.VerifiableCredentialConstants.VC_CLAIM;
import static uk.gov.di.ipv.core.library.domain.VerifiableCredentialConstants.VC_EVIDENCE;
import static uk.gov.di.ipv.core.library.domain.VerifiableCredentialConstants.VC_EVIDENCE_TXN;

public class EvaluateGpg45ScoresHandler
        implements RequestHandler<APIGatewayProxyRequestEvent, APIGatewayProxyResponseEvent> {

    public static final List<Gpg45Profile> ACCEPTED_PROFILES =
            List.of(Gpg45Profile.M1A, Gpg45Profile.M1B);
    public static final JourneyResponse JOURNEY_END = new JourneyResponse("/journey/end");
    public static final JourneyResponse JOURNEY_NEXT = new JourneyResponse("/journey/next");
    public static final String VOT_P2 = "P2";
    private static final Logger LOGGER = LogManager.getLogger();
    private static final Gson gson = new Gson();
    public static final int ONLY = 0;
    private final UserIdentityService userIdentityService;
    private final IpvSessionService ipvSessionService;
    private final Gpg45ProfileEvaluator gpg45ProfileEvaluator;
    private final ConfigurationService configurationService;
    private final AuditService auditService;
    private final String addressCriId;
    private final String componentId;

    public EvaluateGpg45ScoresHandler(
            UserIdentityService userIdentityService,
            IpvSessionService ipvSessionService,
            Gpg45ProfileEvaluator gpg45ProfileEvaluator,
            ConfigurationService configurationService,
            AuditService auditService) {
        this.userIdentityService = userIdentityService;
        this.ipvSessionService = ipvSessionService;
        this.gpg45ProfileEvaluator = gpg45ProfileEvaluator;
        this.configurationService = configurationService;
        this.auditService = auditService;

        addressCriId = configurationService.getSsmParameter(ADDRESS_CRI_ID);
        componentId =
                configurationService.getSsmParameter(ConfigurationVariable.AUDIENCE_FOR_CLIENTS);
    }

    public EvaluateGpg45ScoresHandler() {
        this.configurationService = new ConfigurationService();
        this.userIdentityService = new UserIdentityService(configurationService);
        this.ipvSessionService = new IpvSessionService(configurationService);
        this.gpg45ProfileEvaluator =
                new Gpg45ProfileEvaluator(
                        new CiStorageService(configurationService), configurationService);
        this.auditService =
                new AuditService(AuditService.getDefaultSqsClient(), configurationService);

        addressCriId = configurationService.getSsmParameter(ADDRESS_CRI_ID);
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
            IpvSessionItem ipvSessionItem = ipvSessionService.getIpvSession(ipvSessionId);
            ClientSessionDetailsDto clientSessionDetailsDto =
                    ipvSessionItem.getClientSessionDetails();
            String userId = clientSessionDetailsDto.getUserId();

            String govukSigninJourneyId = clientSessionDetailsDto.getGovukSigninJourneyId();
            LogHelper.attachGovukSigninJourneyIdToLogs(govukSigninJourneyId);

            List<SignedJWT> credentials =
                    gpg45ProfileEvaluator.parseCredentials(
                            userIdentityService.getUserIssuedCredentials(userId));

            Optional<JourneyResponse> contraIndicatorErrorJourneyResponse =
                    gpg45ProfileEvaluator.getJourneyResponseForStoredCis(clientSessionDetailsDto);
            if (contraIndicatorErrorJourneyResponse.isEmpty()) {
                Gpg45Scores gpg45Scores = gpg45ProfileEvaluator.buildScore(credentials);
                Optional<Gpg45Profile> matchedProfile =
                        gpg45ProfileEvaluator.getFirstMatchingProfile(
                                gpg45Scores, ACCEPTED_PROFILES);
                JourneyResponse journeyResponse;
                var message = new MapMessage();

                if (matchedProfile.isPresent()) {
                    auditService.sendAuditEvent(
                            buildProfileMatchedAuditEvent(
                                    ipvSessionItem,
                                    matchedProfile.get(),
                                    gpg45Scores,
                                    credentials));
                    ipvSessionItem.setVot(VOT_P2);
                    journeyResponse = JOURNEY_END;
                    message.with("lambdaResult", "A GPG45 profile has been met")
                            .with("journeyResponse", JOURNEY_END);
                } else {
                    journeyResponse = JOURNEY_NEXT;
                    message.with("lambdaResult", "No GPG45 profiles have been met")
                            .with("journeyResponse", JOURNEY_NEXT);
                }

                updateSuccessfulVcStatuses(ipvSessionItem, credentials);

                LOGGER.info(message);

                return ApiGatewayResponseGenerator.proxyJsonResponse(
                        HttpStatus.SC_OK, journeyResponse);
            } else {
                return ApiGatewayResponseGenerator.proxyJsonResponse(
                        HttpStatus.SC_OK, contraIndicatorErrorJourneyResponse.get());
            }

        } catch (HttpResponseExceptionWithErrorBody e) {
            return ApiGatewayResponseGenerator.proxyJsonResponse(
                    e.getResponseCode(), e.getErrorBody());
        } catch (ParseException e) {
            LOGGER.error("Unable to parse GPG45 scores from existing credentials", e);
            return ApiGatewayResponseGenerator.proxyJsonResponse(
                    HttpStatus.SC_INTERNAL_SERVER_ERROR,
                    ErrorResponse.FAILED_TO_PARSE_ISSUED_CREDENTIALS);
        } catch (UnknownEvidenceTypeException e) {
            LOGGER.error("Unable to determine type of credential", e);
            return ApiGatewayResponseGenerator.proxyJsonResponse(
                    HttpStatus.SC_INTERNAL_SERVER_ERROR,
                    ErrorResponse.FAILED_TO_DETERMINE_CREDENTIAL_TYPE);
        } catch (CiRetrievalException e) {
            LOGGER.error("Error when fetching CIs from storage system", e);
            return ApiGatewayResponseGenerator.proxyJsonResponse(
                    HttpStatus.SC_INTERNAL_SERVER_ERROR, ErrorResponse.FAILED_TO_GET_STORED_CIS);
        } catch (SqsException e) {
            LOGGER.error("Failed to send audit event to SQS queue: {}", e.getMessage());
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

    private List<VcStatusDto> generateVcSuccessStatuses(List<SignedJWT> credentials)
            throws ParseException {
        List<VcStatusDto> vcStatuses = new ArrayList<>();

        for (SignedJWT signedJWT : credentials) {

            CredentialIssuerConfig addressCriConfig =
                    configurationService.getCredentialIssuer(addressCriId);
            boolean isSuccessful = VcHelper.isSuccessfulVc(signedJWT, addressCriConfig, true);

            vcStatuses.add(new VcStatusDto(signedJWT.getJWTClaimsSet().getIssuer(), isSuccessful));
        }
        return vcStatuses;
    }

    private AuditEvent buildProfileMatchedAuditEvent(
            IpvSessionItem ipvSessionItem,
            Gpg45Profile gpg45Profile,
            Gpg45Scores gpg45Scores,
            List<SignedJWT> credentials)
            throws ParseException {
        AuditEventUser auditEventUser =
                new AuditEventUser(
                        ipvSessionItem.getClientSessionDetails().getUserId(),
                        ipvSessionItem.getIpvSessionId(),
                        ipvSessionItem.getClientSessionDetails().getGovukSigninJourneyId());
        return new AuditEvent(
                AuditEventTypes.IPV_GPG45_PROFILE_MATCHED,
                componentId,
                auditEventUser,
                new AuditExtensionGpg45ProfileMatched(
                        gpg45Profile, gpg45Scores, extractTxnIdsFromCredentials(credentials)));
    }

    private List<String> extractTxnIdsFromCredentials(List<SignedJWT> credentials)
            throws ParseException {
        List<String> txnIds = new ArrayList<>();
        for (SignedJWT credential : credentials) {
            var jwtClaimsSet = credential.getJWTClaimsSet();
            var vc = (JSONObject) jwtClaimsSet.getClaim(VC_CLAIM);
            var evidences = (JSONArray) vc.get(VC_EVIDENCE);
            if (evidences != null) { // not all VCs have an evidence block
                var evidence = (JSONObject) evidences.get(ONLY);
                txnIds.add(evidence.getAsString(VC_EVIDENCE_TXN));
            }
        }
        return txnIds;
    }
}
