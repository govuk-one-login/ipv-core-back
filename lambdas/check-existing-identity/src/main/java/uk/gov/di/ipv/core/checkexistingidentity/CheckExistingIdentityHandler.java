package uk.gov.di.ipv.core.checkexistingidentity;

import com.amazonaws.services.lambda.runtime.Context;
import com.nimbusds.jose.shaded.json.JSONArray;
import com.nimbusds.jose.shaded.json.JSONObject;
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
import uk.gov.di.ipv.core.library.auditing.AuditExtensionGpg45ProfileMatched;
import uk.gov.di.ipv.core.library.config.ConfigurationVariable;
import uk.gov.di.ipv.core.library.domain.ContraIndicatorItem;
import uk.gov.di.ipv.core.library.domain.ErrorResponse;
import uk.gov.di.ipv.core.library.domain.JourneyErrorResponse;
import uk.gov.di.ipv.core.library.domain.JourneyRequest;
import uk.gov.di.ipv.core.library.domain.JourneyResponse;
import uk.gov.di.ipv.core.library.domain.gpg45.Gpg45Profile;
import uk.gov.di.ipv.core.library.domain.gpg45.Gpg45ProfileEvaluator;
import uk.gov.di.ipv.core.library.domain.gpg45.Gpg45Scores;
import uk.gov.di.ipv.core.library.domain.gpg45.exception.UnknownEvidenceTypeException;
import uk.gov.di.ipv.core.library.dto.CredentialIssuerConfig;
import uk.gov.di.ipv.core.library.dto.VcStatusDto;
import uk.gov.di.ipv.core.library.exceptions.CiRetrievalException;
import uk.gov.di.ipv.core.library.exceptions.HttpResponseExceptionWithErrorBody;
import uk.gov.di.ipv.core.library.exceptions.SqsException;
import uk.gov.di.ipv.core.library.helpers.LogHelper;
import uk.gov.di.ipv.core.library.helpers.RequestHelper;
import uk.gov.di.ipv.core.library.persistence.item.ClientOAuthSessionItem;
import uk.gov.di.ipv.core.library.persistence.item.IpvSessionItem;
import uk.gov.di.ipv.core.library.persistence.item.VcStoreItem;
import uk.gov.di.ipv.core.library.service.AuditService;
import uk.gov.di.ipv.core.library.service.CiStorageService;
import uk.gov.di.ipv.core.library.service.ClientOAuthSessionDetailsService;
import uk.gov.di.ipv.core.library.service.ConfigService;
import uk.gov.di.ipv.core.library.service.CriResponseService;
import uk.gov.di.ipv.core.library.service.IpvSessionService;
import uk.gov.di.ipv.core.library.service.UserIdentityService;
import uk.gov.di.ipv.core.library.statemachine.JourneyRequestLambda;
import uk.gov.di.ipv.core.library.vchelper.VcHelper;

import java.text.ParseException;
import java.util.ArrayList;
import java.util.List;
import java.util.Objects;
import java.util.Optional;

import static uk.gov.di.ipv.core.library.domain.CriConstants.ADDRESS_CRI;
import static uk.gov.di.ipv.core.library.domain.CriConstants.CLAIMED_IDENTITY_CRI;
import static uk.gov.di.ipv.core.library.domain.CriConstants.F2F_CRI;
import static uk.gov.di.ipv.core.library.domain.VerifiableCredentialConstants.VC_CLAIM;
import static uk.gov.di.ipv.core.library.domain.VerifiableCredentialConstants.VC_EVIDENCE;
import static uk.gov.di.ipv.core.library.domain.VerifiableCredentialConstants.VC_EVIDENCE_TXN;
import static uk.gov.di.ipv.core.library.helpers.LogHelper.LogField.LOG_MESSAGE_DESCRIPTION;
import static uk.gov.di.ipv.core.library.helpers.LogHelper.LogField.LOG_PROFILE;
import static uk.gov.di.ipv.core.library.helpers.RequestHelper.getIpAddress;
import static uk.gov.di.ipv.core.library.helpers.RequestHelper.getIpvSessionId;

/** Check Existing Identity response Lambda */
public class CheckExistingIdentityHandler extends JourneyRequestLambda {
    private static final List<Gpg45Profile> ACCEPTED_PROFILES =
            List.of(Gpg45Profile.M1A, Gpg45Profile.M1B);
    private static final String VOT_P2 = "P2";
    private static final int ONLY = 0;
    private static final Logger LOGGER = LogManager.getLogger();

    private static final JourneyResponse JOURNEY_REUSE = new JourneyResponse("/journey/reuse");
    private static final JourneyResponse JOURNEY_NEXT = new JourneyResponse("/journey/next");

    private final ConfigService configService;
    private final UserIdentityService userIdentityService;
    private final CriResponseService criResponseService;
    private final IpvSessionService ipvSessionService;
    private final Gpg45ProfileEvaluator gpg45ProfileEvaluator;
    private final CiStorageService ciStorageService;
    private final AuditService auditService;
    private final ClientOAuthSessionDetailsService clientOAuthSessionDetailsService;
    private final String componentId;

    @SuppressWarnings("unused") // Used by AWS
    public CheckExistingIdentityHandler(
            ConfigService configService,
            UserIdentityService userIdentityService,
            IpvSessionService ipvSessionService,
            Gpg45ProfileEvaluator gpg45ProfileEvaluator,
            CiStorageService ciStorageService,
            AuditService auditService,
            ClientOAuthSessionDetailsService clientOAuthSessionDetailsService,
            CriResponseService criResponseService) {
        this.configService = configService;
        this.userIdentityService = userIdentityService;
        this.ipvSessionService = ipvSessionService;
        this.gpg45ProfileEvaluator = gpg45ProfileEvaluator;
        this.ciStorageService = ciStorageService;
        this.auditService = auditService;
        this.clientOAuthSessionDetailsService = clientOAuthSessionDetailsService;
        this.componentId = configService.getSsmParameter(ConfigurationVariable.COMPONENT_ID);
        this.criResponseService = criResponseService;
    }

    @SuppressWarnings("unused") // Used through dependency injection
    @ExcludeFromGeneratedCoverageReport
    public CheckExistingIdentityHandler() {
        this.configService = new ConfigService();
        this.userIdentityService = new UserIdentityService(configService);
        this.ipvSessionService = new IpvSessionService(configService);
        this.gpg45ProfileEvaluator = new Gpg45ProfileEvaluator(configService);
        this.ciStorageService = new CiStorageService(configService);
        this.auditService = new AuditService(AuditService.getDefaultSqsClient(), configService);
        this.clientOAuthSessionDetailsService = new ClientOAuthSessionDetailsService(configService);
        componentId = configService.getSsmParameter(ConfigurationVariable.COMPONENT_ID);
        this.criResponseService = new CriResponseService(configService);
    }

    @Override
    @Tracing
    @Logging(clearState = true)
    public JourneyResponse handleRequest(JourneyRequest event, Context context) {
        LogHelper.attachComponentIdToLogs();

        try {
            String ipvSessionId = getIpvSessionId(event);
            String ipAddress = getIpAddress(event);
            String featureSet = RequestHelper.getFeatureSet(event);
            configService.setFeatureSet(featureSet);
            IpvSessionItem ipvSessionItem = ipvSessionService.getIpvSession(ipvSessionId);
            ClientOAuthSessionItem clientOAuthSessionItem =
                    clientOAuthSessionDetailsService.getClientOAuthSession(
                            ipvSessionItem.getClientOAuthSessionId());
            String userId = clientOAuthSessionItem.getUserId();

            String govukSigninJourneyId = clientOAuthSessionItem.getGovukSigninJourneyId();
            LogHelper.attachGovukSigninJourneyIdToLogs(govukSigninJourneyId);

            AuditEventUser auditEventUser =
                    new AuditEventUser(userId, ipvSessionId, govukSigninJourneyId, ipAddress);

            boolean userHasFaceToFaceRequest = criResponseService.userHasFaceToFaceRequest(userId);
            VcStoreItem faceToFaceVc = userIdentityService.getVcStoreItem(userId, F2F_CRI);

            List<SignedJWT> credentials =
                    gpg45ProfileEvaluator.parseCredentials(
                            userIdentityService.getUserIssuedCredentials(userId));

            List<ContraIndicatorItem> ciItems;
            ciItems =
                    ciStorageService.getCIs(
                            clientOAuthSessionItem.getUserId(),
                            clientOAuthSessionItem.getGovukSigninJourneyId(),
                            ipAddress);

            Optional<JourneyResponse> contraIndicatorErrorJourneyResponse =
                    gpg45ProfileEvaluator.getJourneyResponseForStoredCis(ciItems);
            if (contraIndicatorErrorJourneyResponse.isEmpty()) {
                Gpg45Scores gpg45Scores = gpg45ProfileEvaluator.buildScore(credentials);
                Optional<Gpg45Profile> matchedProfile =
                        gpg45ProfileEvaluator.getFirstMatchingProfile(
                                gpg45Scores, ACCEPTED_PROFILES);
                if (matchedProfile.isPresent()) {
                    auditService.sendAuditEvent(
                            buildProfileMatchedAuditEvent(
                                    ipvSessionItem,
                                    clientOAuthSessionItem,
                                    matchedProfile.get(),
                                    gpg45Scores,
                                    credentials,
                                    ipAddress));

                    var message =
                            new StringMapMessage()
                                    .with(
                                            LOG_MESSAGE_DESCRIPTION.getFieldName(),
                                            "Matched profile and within CI threshold so returning reuse journey.")
                                    .with(
                                            LOG_PROFILE.getFieldName(),
                                            matchedProfile.get().getLabel());
                    LOGGER.info(message);

                    auditService.sendAuditEvent(
                            new AuditEvent(
                                    AuditEventTypes.IPV_IDENTITY_REUSE_COMPLETE,
                                    componentId,
                                    auditEventUser));

                    ipvSessionItem.setVot(VOT_P2);

                    updateSuccessfulVcStatuses(ipvSessionItem, credentials);

                    return JOURNEY_REUSE;
                }
            }

            if (userHasFaceToFaceRequest) {
                if (Objects.isNull(faceToFaceVc)) {
                    var message =
                            new StringMapMessage()
                                    .with(
                                            LOG_MESSAGE_DESCRIPTION.getFieldName(),
                                            "F2F cri pending verification. No VC to delete.");
                    LOGGER.info(message);
                } else {
                    userIdentityService.deleteVcStoreItems(userId);
                    var message =
                            new StringMapMessage()
                                    .with(
                                            LOG_MESSAGE_DESCRIPTION.getFieldName(),
                                            "F2F cri pending verification. Existing F2F VC deleted.");
                    LOGGER.info(message);
                }

                return JOURNEY_NEXT;
            }

            if (!credentials.isEmpty()) {
                var message =
                        new StringMapMessage()
                                .with(
                                        LOG_MESSAGE_DESCRIPTION.getFieldName(),
                                        "Failed to match profile so clearing VCs and returning next.");
                LOGGER.info(message);

                auditService.sendAuditEvent(
                        new AuditEvent(
                                AuditEventTypes.IPV_IDENTITY_REUSE_RESET,
                                componentId,
                                auditEventUser));

                userIdentityService.deleteVcStoreItems(userId);
            } else {
                var message =
                        new StringMapMessage()
                                .with(
                                        LOG_MESSAGE_DESCRIPTION.getFieldName(),
                                        "New user so returning next.");
                LOGGER.info(message);
            }

            return JOURNEY_NEXT;
        } catch (HttpResponseExceptionWithErrorBody e) {
            LOGGER.error("Unable to parse existing credentials", e);
            return new JourneyErrorResponse(
                    JOURNEY_ERROR_PATH, e.getResponseCode(), e.getErrorResponse());
        } catch (ParseException e) {
            LOGGER.error("Unable to parse existing credentials", e);
            return new JourneyErrorResponse(
                    JOURNEY_ERROR_PATH,
                    HttpStatus.SC_INTERNAL_SERVER_ERROR,
                    ErrorResponse.FAILED_TO_PARSE_ISSUED_CREDENTIALS);
        } catch (CiRetrievalException e) {
            LOGGER.error("Error when fetching CIs from storage system", e);
            return new JourneyErrorResponse(
                    JOURNEY_ERROR_PATH,
                    HttpStatus.SC_INTERNAL_SERVER_ERROR,
                    ErrorResponse.FAILED_TO_GET_STORED_CIS);
        } catch (UnknownEvidenceTypeException e) {
            LOGGER.error("Unable to determine type of credential", e);
            return new JourneyErrorResponse(
                    JOURNEY_ERROR_PATH,
                    HttpStatus.SC_INTERNAL_SERVER_ERROR,
                    ErrorResponse.FAILED_TO_DETERMINE_CREDENTIAL_TYPE);
        } catch (SqsException e) {
            LOGGER.error("Failed to send audit event to SQS queue", e);
            return new JourneyErrorResponse(
                    JOURNEY_ERROR_PATH,
                    HttpStatus.SC_INTERNAL_SERVER_ERROR,
                    ErrorResponse.FAILED_TO_SEND_AUDIT_EVENT);
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
        for (SignedJWT signedJWT : credentials) {

            List<CredentialIssuerConfig> excludedCriConfigs =
                    List.of(
                            configService.getCredentialIssuerActiveConnectionConfig(ADDRESS_CRI),
                            configService.getCredentialIssuerActiveConnectionConfig(
                                    CLAIMED_IDENTITY_CRI));
            boolean isSuccessful = VcHelper.isSuccessfulVcIgnoringCi(signedJWT, excludedCriConfigs);

            vcStatuses.add(new VcStatusDto(signedJWT.getJWTClaimsSet().getIssuer(), isSuccessful));
        }
        return vcStatuses;
    }

    private AuditEvent buildProfileMatchedAuditEvent(
            IpvSessionItem ipvSessionItem,
            ClientOAuthSessionItem clientOAuthSessionItem,
            Gpg45Profile gpg45Profile,
            Gpg45Scores gpg45Scores,
            List<SignedJWT> credentials,
            String ipAddress)
            throws ParseException {
        AuditEventUser auditEventUser =
                new AuditEventUser(
                        clientOAuthSessionItem.getUserId(),
                        ipvSessionItem.getIpvSessionId(),
                        clientOAuthSessionItem.getGovukSigninJourneyId(),
                        ipAddress);
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
