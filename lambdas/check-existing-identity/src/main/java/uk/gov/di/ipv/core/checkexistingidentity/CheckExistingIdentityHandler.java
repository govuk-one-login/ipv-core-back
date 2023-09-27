package uk.gov.di.ipv.core.checkexistingidentity;

import com.amazonaws.services.lambda.runtime.Context;
import com.amazonaws.services.lambda.runtime.RequestHandler;
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
import uk.gov.di.ipv.core.library.auditing.extension.AuditExtensionGpg45ProfileMatched;
import uk.gov.di.ipv.core.library.config.ConfigurationVariable;
import uk.gov.di.ipv.core.library.domain.ErrorResponse;
import uk.gov.di.ipv.core.library.domain.JourneyErrorResponse;
import uk.gov.di.ipv.core.library.domain.JourneyRequest;
import uk.gov.di.ipv.core.library.domain.JourneyResponse;
import uk.gov.di.ipv.core.library.dto.VcStatusDto;
import uk.gov.di.ipv.core.library.exceptions.CredentialParseException;
import uk.gov.di.ipv.core.library.exceptions.HttpResponseExceptionWithErrorBody;
import uk.gov.di.ipv.core.library.exceptions.SqsException;
import uk.gov.di.ipv.core.library.gpg45.Gpg45ProfileEvaluator;
import uk.gov.di.ipv.core.library.gpg45.Gpg45Scores;
import uk.gov.di.ipv.core.library.gpg45.enums.Gpg45Profile;
import uk.gov.di.ipv.core.library.gpg45.exception.UnknownEvidenceTypeException;
import uk.gov.di.ipv.core.library.helpers.LogHelper;
import uk.gov.di.ipv.core.library.helpers.RequestHelper;
import uk.gov.di.ipv.core.library.persistence.item.ClientOAuthSessionItem;
import uk.gov.di.ipv.core.library.persistence.item.CriResponseItem;
import uk.gov.di.ipv.core.library.persistence.item.IpvSessionItem;
import uk.gov.di.ipv.core.library.persistence.item.VcStoreItem;
import uk.gov.di.ipv.core.library.service.AuditService;
import uk.gov.di.ipv.core.library.service.ClientOAuthSessionDetailsService;
import uk.gov.di.ipv.core.library.service.ConfigService;
import uk.gov.di.ipv.core.library.service.CriResponseService;
import uk.gov.di.ipv.core.library.service.IpvSessionService;
import uk.gov.di.ipv.core.library.service.UserIdentityService;
import uk.gov.di.ipv.core.library.vchelper.VcHelper;

import java.text.ParseException;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Optional;
import java.util.StringJoiner;

import static uk.gov.di.ipv.core.library.domain.CriConstants.F2F_CRI;
import static uk.gov.di.ipv.core.library.domain.VerifiableCredentialConstants.VC_CLAIM;
import static uk.gov.di.ipv.core.library.domain.VerifiableCredentialConstants.VC_EVIDENCE;
import static uk.gov.di.ipv.core.library.domain.VerifiableCredentialConstants.VC_EVIDENCE_TXN;
import static uk.gov.di.ipv.core.library.helpers.LogHelper.LogField.LOG_ERROR_CODE;
import static uk.gov.di.ipv.core.library.helpers.LogHelper.LogField.LOG_ERROR_DESCRIPTION;
import static uk.gov.di.ipv.core.library.helpers.LogHelper.LogField.LOG_MESSAGE_DESCRIPTION;
import static uk.gov.di.ipv.core.library.helpers.LogHelper.LogField.LOG_PROFILE;
import static uk.gov.di.ipv.core.library.helpers.LogHelper.LogField.LOG_UNCORRELATABLE_DATA;
import static uk.gov.di.ipv.core.library.helpers.RequestHelper.getIpAddress;
import static uk.gov.di.ipv.core.library.helpers.RequestHelper.getIpvSessionId;
import static uk.gov.di.ipv.core.library.journeyuris.JourneyUris.JOURNEY_ERROR_PATH;
import static uk.gov.di.ipv.core.library.journeyuris.JourneyUris.JOURNEY_FAIL_PATH;
import static uk.gov.di.ipv.core.library.journeyuris.JourneyUris.JOURNEY_NEXT_PATH;
import static uk.gov.di.ipv.core.library.journeyuris.JourneyUris.JOURNEY_PENDING_PATH;
import static uk.gov.di.ipv.core.library.journeyuris.JourneyUris.JOURNEY_RESET_IDENTITY_PATH;
import static uk.gov.di.ipv.core.library.journeyuris.JourneyUris.JOURNEY_REUSE_PATH;

/** Check Existing Identity response Lambda */
public class CheckExistingIdentityHandler
        implements RequestHandler<JourneyRequest, Map<String, Object>> {
    private static final List<Gpg45Profile> ACCEPTED_PROFILES =
            List.of(Gpg45Profile.M1A, Gpg45Profile.M1B);
    private static final int ONLY = 0;
    private static final Logger LOGGER = LogManager.getLogger();

    private static final Map<String, Object> JOURNEY_REUSE =
            new JourneyResponse(JOURNEY_REUSE_PATH).toObjectMap();
    private static final Map<String, Object> JOURNEY_PENDING =
            new JourneyResponse(JOURNEY_PENDING_PATH).toObjectMap();
    private static final Map<String, Object> JOURNEY_NEXT =
            new JourneyResponse(JOURNEY_NEXT_PATH).toObjectMap();
    private static final Map<String, Object> JOURNEY_FAIL =
            new JourneyResponse(JOURNEY_FAIL_PATH).toObjectMap();
    private static final Map<String, Object> JOURNEY_RESET_IDENTITY =
            new JourneyResponse(JOURNEY_RESET_IDENTITY_PATH).toObjectMap();
    public static final String NAMES = "names";
    public static final String DATE_OF_BIRTH = "dob";
    public static final String VOT_P2 = "P2";

    private final ConfigService configService;
    private final UserIdentityService userIdentityService;
    private final CriResponseService criResponseService;
    private final IpvSessionService ipvSessionService;
    private final Gpg45ProfileEvaluator gpg45ProfileEvaluator;
    private final AuditService auditService;
    private final ClientOAuthSessionDetailsService clientOAuthSessionDetailsService;

    @SuppressWarnings("unused") // Used by AWS
    public CheckExistingIdentityHandler(
            ConfigService configService,
            UserIdentityService userIdentityService,
            IpvSessionService ipvSessionService,
            Gpg45ProfileEvaluator gpg45ProfileEvaluator,
            AuditService auditService,
            ClientOAuthSessionDetailsService clientOAuthSessionDetailsService,
            CriResponseService criResponseService) {
        this.configService = configService;
        this.userIdentityService = userIdentityService;
        this.ipvSessionService = ipvSessionService;
        this.gpg45ProfileEvaluator = gpg45ProfileEvaluator;
        this.auditService = auditService;
        this.clientOAuthSessionDetailsService = clientOAuthSessionDetailsService;
        this.criResponseService = criResponseService;
        VcHelper.setConfigService(this.configService);
    }

    @SuppressWarnings("unused") // Used through dependency injection
    @ExcludeFromGeneratedCoverageReport
    public CheckExistingIdentityHandler() {
        this.configService = new ConfigService();
        this.userIdentityService = new UserIdentityService(configService);
        this.ipvSessionService = new IpvSessionService(configService);
        this.gpg45ProfileEvaluator = new Gpg45ProfileEvaluator(configService, ipvSessionService);
        this.auditService = new AuditService(AuditService.getDefaultSqsClient(), configService);
        this.clientOAuthSessionDetailsService = new ClientOAuthSessionDetailsService(configService);
        this.criResponseService = new CriResponseService(configService);
        VcHelper.setConfigService(this.configService);
    }

    @Override
    @Tracing
    @Logging(clearState = true)
    public Map<String, Object> handleRequest(JourneyRequest event, Context context) {
        LogHelper.attachComponentIdToLogs(configService);

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

            CriResponseItem f2fRequest = criResponseService.getFaceToFaceRequest(userId);
            VcStoreItem f2fVc = userIdentityService.getVcStoreItem(userId, F2F_CRI);

            Optional<Map<String, Object>> f2fResponse = getFaceToFaceResponse(f2fRequest, f2fVc);
            if (f2fResponse.isPresent()) {
                return f2fResponse.get();
            }

            List<SignedJWT> credentials =
                    gpg45ProfileEvaluator.parseCredentials(
                            userIdentityService.getUserIssuedCredentials(userId));
            updateSuccessfulVcStatuses(ipvSessionItem, credentials);

            boolean dataCorrelates = vcDataCorrelates(userId);
            if (!dataCorrelates && completedF2F(f2fRequest, f2fVc)) {
                return JOURNEY_FAIL;
            } else if (!dataCorrelates) {
                LOGGER.info(
                        new StringMapMessage()
                                .with(
                                        LOG_MESSAGE_DESCRIPTION.getFieldName(),
                                        "VC data does not correlate so resetting identity."));

                auditService.sendAuditEvent(
                        new AuditEvent(
                                AuditEventTypes.IPV_IDENTITY_REUSE_RESET,
                                configService.getSsmParameter(ConfigurationVariable.COMPONENT_ID),
                                auditEventUser));

                return JOURNEY_RESET_IDENTITY;
            }

            Gpg45Scores gpg45Scores = gpg45ProfileEvaluator.buildScore(credentials);
            Optional<Gpg45Profile> matchedProfile =
                    gpg45ProfileEvaluator.getFirstMatchingProfile(gpg45Scores, ACCEPTED_PROFILES);

            if (matchedProfile.isEmpty() && completedF2F(f2fRequest, f2fVc)) {
                var message =
                        new StringMapMessage()
                                .with(
                                        LOG_MESSAGE_DESCRIPTION.getFieldName(),
                                        "F2F return - failed to match a profile.");
                LOGGER.info(message);
                return JOURNEY_FAIL;
            }

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
                                .with(LOG_PROFILE.getFieldName(), matchedProfile.get().getLabel());
                LOGGER.info(message);

                auditService.sendAuditEvent(
                        new AuditEvent(
                                AuditEventTypes.IPV_IDENTITY_REUSE_COMPLETE,
                                configService.getSsmParameter(ConfigurationVariable.COMPONENT_ID),
                                auditEventUser));

                ipvSessionItem.setVot(VOT_P2);
                ipvSessionService.updateIpvSession(ipvSessionItem);

                return JOURNEY_REUSE;
            }

            if (!credentials.isEmpty()) {
                var message =
                        new StringMapMessage()
                                .with(
                                        LOG_MESSAGE_DESCRIPTION.getFieldName(),
                                        "Failed to match profile so resetting identity.");
                LOGGER.info(message);

                auditService.sendAuditEvent(
                        new AuditEvent(
                                AuditEventTypes.IPV_IDENTITY_REUSE_RESET,
                                configService.getSsmParameter(ConfigurationVariable.COMPONENT_ID),
                                auditEventUser));

                return JOURNEY_RESET_IDENTITY;
            }

            var message =
                    new StringMapMessage()
                            .with(
                                    LOG_MESSAGE_DESCRIPTION.getFieldName(),
                                    "New user so returning next.");
            LOGGER.info(message);

            return JOURNEY_NEXT;
        } catch (HttpResponseExceptionWithErrorBody e) {
            LOGGER.error("Unable to parse existing credentials", e);
            return new JourneyErrorResponse(
                            JOURNEY_ERROR_PATH, e.getResponseCode(), e.getErrorResponse())
                    .toObjectMap();
        } catch (ParseException e) {
            LOGGER.error("Unable to parse existing credentials", e);
            return new JourneyErrorResponse(
                            JOURNEY_ERROR_PATH,
                            HttpStatus.SC_INTERNAL_SERVER_ERROR,
                            ErrorResponse.FAILED_TO_PARSE_ISSUED_CREDENTIALS)
                    .toObjectMap();
        } catch (UnknownEvidenceTypeException e) {
            LOGGER.error("Unable to determine type of credential", e);
            return new JourneyErrorResponse(
                            JOURNEY_ERROR_PATH,
                            HttpStatus.SC_INTERNAL_SERVER_ERROR,
                            ErrorResponse.FAILED_TO_DETERMINE_CREDENTIAL_TYPE)
                    .toObjectMap();
        } catch (SqsException e) {
            LOGGER.error("Failed to send audit event to SQS queue", e);
            return new JourneyErrorResponse(
                            JOURNEY_ERROR_PATH,
                            HttpStatus.SC_INTERNAL_SERVER_ERROR,
                            ErrorResponse.FAILED_TO_SEND_AUDIT_EVENT)
                    .toObjectMap();
        } catch (CredentialParseException e) {
            LOGGER.error("Failed to parse successful VC Store items.", e);
            return new JourneyErrorResponse(
                            JOURNEY_ERROR_PATH,
                            HttpStatus.SC_INTERNAL_SERVER_ERROR,
                            ErrorResponse.FAILED_TO_PARSE_SUCCESSFUL_VC_STORE_ITEMS)
                    .toObjectMap();
        }
    }

    @Tracing
    private Optional<Map<String, Object>> getFaceToFaceResponse(
            CriResponseItem faceToFaceRequest, VcStoreItem faceToFaceVc) {
        if (Objects.isNull(faceToFaceVc) && !Objects.isNull(faceToFaceRequest)) {
            final String requestStatus = faceToFaceRequest.getStatus();
            if (requestStatus.equals(CriResponseService.STATUS_PENDING)) {
                LOGGER.info(
                        new StringMapMessage()
                                .with(
                                        LOG_MESSAGE_DESCRIPTION.getFieldName(),
                                        "F2F cri pending verification."));

                return Optional.of(JOURNEY_PENDING);
            }
            if (requestStatus.equals(CriResponseService.STATUS_ERROR)) {
                LOGGER.info(
                        new StringMapMessage()
                                .with(LOG_MESSAGE_DESCRIPTION.getFieldName(), "F2F cri error"));
                return Optional.of(JOURNEY_FAIL);
            }
        }
        return Optional.empty();
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
            boolean isSuccessful = VcHelper.isSuccessfulVcIgnoringCi(signedJWT);
            vcStatuses.add(new VcStatusDto(signedJWT.getJWTClaimsSet().getIssuer(), isSuccessful));
        }
        return vcStatuses;
    }

    @Tracing
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
                configService.getSsmParameter(ConfigurationVariable.COMPONENT_ID),
                auditEventUser,
                new AuditExtensionGpg45ProfileMatched(
                        gpg45Profile, gpg45Scores, extractTxnIdsFromCredentials(credentials)));
    }

    @Tracing
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

    @Tracing
    private boolean vcDataCorrelates(String userId)
            throws HttpResponseExceptionWithErrorBody, CredentialParseException {
        StringJoiner uncorrelatableData = new StringJoiner(",");
        if (!userIdentityService.checkNameAndFamilyNameCorrelationInCredentials(userId)) {
            uncorrelatableData.add(NAMES);
        }

        if (!userIdentityService.checkBirthDateCorrelationInCredentials(userId)) {
            uncorrelatableData.add(DATE_OF_BIRTH);
        }

        if (uncorrelatableData.length() > 0) {
            LOGGER.error(
                    new StringMapMessage()
                            .with(
                                    LOG_ERROR_CODE.getFieldName(),
                                    ErrorResponse.FAILED_TO_CORRELATE_DATA.getCode())
                            .with(
                                    LOG_ERROR_DESCRIPTION.getFieldName(),
                                    ErrorResponse.FAILED_TO_CORRELATE_DATA.getMessage())
                            .with(LOG_UNCORRELATABLE_DATA.getFieldName(), uncorrelatableData));
            return false;
        }
        return true;
    }

    private boolean completedF2F(CriResponseItem request, VcStoreItem vc) {
        return request != null && vc != null;
    }
}
