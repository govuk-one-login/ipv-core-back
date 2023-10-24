package uk.gov.di.ipv.core.evaluategpg45scores;

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
import uk.gov.di.ipv.core.library.dto.VisitedCredentialIssuerDetailsDto;
import uk.gov.di.ipv.core.library.exceptions.CredentialParseException;
import uk.gov.di.ipv.core.library.exceptions.HttpResponseExceptionWithErrorBody;
import uk.gov.di.ipv.core.library.exceptions.NoVisitedCriFoundException;
import uk.gov.di.ipv.core.library.exceptions.SqsException;
import uk.gov.di.ipv.core.library.gpg45.Gpg45ProfileEvaluator;
import uk.gov.di.ipv.core.library.gpg45.Gpg45Scores;
import uk.gov.di.ipv.core.library.gpg45.enums.Gpg45Profile;
import uk.gov.di.ipv.core.library.gpg45.exception.UnknownEvidenceTypeException;
import uk.gov.di.ipv.core.library.helpers.LogHelper;
import uk.gov.di.ipv.core.library.helpers.RequestHelper;
import uk.gov.di.ipv.core.library.persistence.item.ClientOAuthSessionItem;
import uk.gov.di.ipv.core.library.persistence.item.IpvSessionItem;
import uk.gov.di.ipv.core.library.service.AuditService;
import uk.gov.di.ipv.core.library.service.ClientOAuthSessionDetailsService;
import uk.gov.di.ipv.core.library.service.ConfigService;
import uk.gov.di.ipv.core.library.service.IpvSessionService;
import uk.gov.di.ipv.core.library.service.UserIdentityService;
import uk.gov.di.ipv.core.library.verifiablecredential.helpers.VcHelper;

import java.text.ParseException;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.Optional;

import static uk.gov.di.ipv.core.library.domain.VerifiableCredentialConstants.VC_CLAIM;
import static uk.gov.di.ipv.core.library.domain.VerifiableCredentialConstants.VC_EVIDENCE;
import static uk.gov.di.ipv.core.library.domain.VerifiableCredentialConstants.VC_EVIDENCE_TXN;
import static uk.gov.di.ipv.core.library.helpers.LogHelper.LogField.LOG_ERROR_CODE;
import static uk.gov.di.ipv.core.library.helpers.LogHelper.LogField.LOG_ERROR_DESCRIPTION;
import static uk.gov.di.ipv.core.library.helpers.LogHelper.LogField.LOG_ERROR_JOURNEY_RESPONSE;
import static uk.gov.di.ipv.core.library.helpers.LogHelper.LogField.LOG_MESSAGE_DESCRIPTION;
import static uk.gov.di.ipv.core.library.journeyuris.JourneyUris.JOURNEY_END_PATH;
import static uk.gov.di.ipv.core.library.journeyuris.JourneyUris.JOURNEY_ERROR_PATH;
import static uk.gov.di.ipv.core.library.journeyuris.JourneyUris.JOURNEY_FAIL_WITH_NO_CI_PATH;
import static uk.gov.di.ipv.core.library.journeyuris.JourneyUris.JOURNEY_NEXT_PATH;
import static uk.gov.di.ipv.core.library.journeyuris.JourneyUris.JOURNEY_PYI_NO_MATCH_PATH;

/** Evaluate the gathered credentials against a desired GPG45 profile. */
public class EvaluateGpg45ScoresHandler
        implements RequestHandler<JourneyRequest, Map<String, Object>> {
    private static final List<Gpg45Profile> ACCEPTED_PROFILES =
            List.of(Gpg45Profile.M1A, Gpg45Profile.M1B);
    private static final JourneyResponse JOURNEY_END = new JourneyResponse(JOURNEY_END_PATH);
    private static final JourneyResponse JOURNEY_NEXT = new JourneyResponse(JOURNEY_NEXT_PATH);
    private static final JourneyResponse JOURNEY_PYI_NO_MATCH =
            new JourneyResponse(JOURNEY_PYI_NO_MATCH_PATH);
    private static final JourneyResponse JOURNEY_FAIL_WITH_NO_CI =
            new JourneyResponse(JOURNEY_FAIL_WITH_NO_CI_PATH);

    private static final Logger LOGGER = LogManager.getLogger();
    private static final int ONLY = 0;
    private final UserIdentityService userIdentityService;
    private final IpvSessionService ipvSessionService;
    private final Gpg45ProfileEvaluator gpg45ProfileEvaluator;
    private final ConfigService configService;
    private final AuditService auditService;
    private final ClientOAuthSessionDetailsService clientOAuthSessionDetailsService;
    public static final String VOT_P2 = "P2";

    @SuppressWarnings("unused") // Used by tests through injection
    public EvaluateGpg45ScoresHandler(
            UserIdentityService userIdentityService,
            IpvSessionService ipvSessionService,
            Gpg45ProfileEvaluator gpg45ProfileEvaluator,
            ConfigService configService,
            AuditService auditService,
            ClientOAuthSessionDetailsService clientOAuthSessionDetailsService) {
        this.userIdentityService = userIdentityService;
        this.ipvSessionService = ipvSessionService;
        this.gpg45ProfileEvaluator = gpg45ProfileEvaluator;
        this.configService = configService;
        this.auditService = auditService;
        this.clientOAuthSessionDetailsService = clientOAuthSessionDetailsService;
        VcHelper.setConfigService(this.configService);
    }

    @SuppressWarnings("unused") // Used by AWS
    @ExcludeFromGeneratedCoverageReport
    public EvaluateGpg45ScoresHandler() {
        this.configService = new ConfigService();
        this.userIdentityService = new UserIdentityService(configService);
        this.ipvSessionService = new IpvSessionService(configService);
        this.gpg45ProfileEvaluator = new Gpg45ProfileEvaluator(configService, ipvSessionService);
        this.auditService = new AuditService(AuditService.getDefaultSqsClient(), configService);
        this.clientOAuthSessionDetailsService = new ClientOAuthSessionDetailsService(configService);
        VcHelper.setConfigService(this.configService);
    }

    @Override
    @Tracing
    @Logging(clearState = true)
    public Map<String, Object> handleRequest(JourneyRequest event, Context context) {
        LogHelper.attachComponentIdToLogs(configService);

        try {
            String ipvSessionId = RequestHelper.getIpvSessionId(event);
            String ipAddress = RequestHelper.getIpAddress(event);
            String featureSet = RequestHelper.getFeatureSet(event);
            configService.setFeatureSet(featureSet);
            IpvSessionItem ipvSessionItem = ipvSessionService.getIpvSession(ipvSessionId);
            ClientOAuthSessionItem clientOAuthSessionItem =
                    clientOAuthSessionDetailsService.getClientOAuthSession(
                            ipvSessionItem.getClientOAuthSessionId());
            String userId = clientOAuthSessionItem.getUserId();

            String govukSigninJourneyId = clientOAuthSessionItem.getGovukSigninJourneyId();
            LogHelper.attachGovukSigninJourneyIdToLogs(govukSigninJourneyId);

            List<SignedJWT> credentials =
                    gpg45ProfileEvaluator.parseCredentials(
                            userIdentityService.getUserIssuedCredentials(userId));

            if (!checkCorrelation(userId)) {
                return JOURNEY_PYI_NO_MATCH.toObjectMap();
            }

            Optional<JourneyResponse> journeyResponseForFailWithNoCi =
                    getJourneyResponseForFailWithNoCi(ipvSessionItem, userId);
            if (journeyResponseForFailWithNoCi.isPresent()) {
                return journeyResponseForFailWithNoCi.get().toObjectMap();
            }

            return checkForMatchingGpg45Profile(
                            ipvSessionItem, clientOAuthSessionItem, credentials, ipAddress)
                    .toObjectMap();
        } catch (HttpResponseExceptionWithErrorBody e) {
            LOGGER.error("Received HTTP response exception", e);
            return new JourneyErrorResponse(
                            JOURNEY_ERROR_PATH, e.getResponseCode(), e.getErrorResponse())
                    .toObjectMap();
        } catch (ParseException e) {
            LOGGER.error("Unable to parse GPG45 scores from existing credentials", e);
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
            LogHelper.logErrorMessage("Failed to send audit event to SQS queue.", e.getMessage());
            return new JourneyErrorResponse(
                            JOURNEY_ERROR_PATH,
                            HttpStatus.SC_INTERNAL_SERVER_ERROR,
                            ErrorResponse.FAILED_TO_SEND_AUDIT_EVENT)
                    .toObjectMap();
        } catch (NoVisitedCriFoundException e) {
            LOGGER.error("No visited CRIs found.", e);
            return new JourneyErrorResponse(
                            JOURNEY_ERROR_PATH,
                            HttpStatus.SC_INTERNAL_SERVER_ERROR,
                            ErrorResponse.FAILED_TO_FIND_VISITED_CRI)
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

    private boolean checkCorrelation(String userId)
            throws HttpResponseExceptionWithErrorBody, CredentialParseException {
        if (!userIdentityService.checkNameAndFamilyNameCorrelationInCredentials(userId)) {
            var message = new StringMapMessage();
            message.with(
                            LOG_ERROR_CODE.getFieldName(),
                            ErrorResponse.FAILED_NAME_CORRELATION.getCode())
                    .with(
                            LOG_ERROR_DESCRIPTION.getFieldName(),
                            ErrorResponse.FAILED_NAME_CORRELATION.getMessage())
                    .with(LOG_ERROR_JOURNEY_RESPONSE.getFieldName(), JOURNEY_PYI_NO_MATCH);
            LOGGER.error(message);
            return false;
        }

        if (!userIdentityService.checkBirthDateCorrelationInCredentials(userId)) {
            var message = new StringMapMessage();
            message.with(
                            LOG_ERROR_CODE.getFieldName(),
                            ErrorResponse.FAILED_BIRTHDATE_CORRELATION.getCode())
                    .with(
                            LOG_ERROR_DESCRIPTION.getFieldName(),
                            ErrorResponse.FAILED_BIRTHDATE_CORRELATION.getMessage())
                    .with(LOG_ERROR_JOURNEY_RESPONSE.getFieldName(), JOURNEY_PYI_NO_MATCH);
            LOGGER.error(message);
            return false;
        }
        return true;
    }

    @Tracing
    private JourneyResponse checkForMatchingGpg45Profile(
            IpvSessionItem ipvSessionItem,
            ClientOAuthSessionItem clientOAuthSessionItem,
            List<SignedJWT> credentials,
            String ipAddress)
            throws UnknownEvidenceTypeException, ParseException, SqsException {
        Gpg45Scores gpg45Scores = gpg45ProfileEvaluator.buildScore(credentials);
        Optional<Gpg45Profile> matchedProfile =
                gpg45ProfileEvaluator.getFirstMatchingProfile(gpg45Scores, ACCEPTED_PROFILES);

        if (matchedProfile.isPresent()) {
            auditService.sendAuditEvent(
                    buildProfileMatchedAuditEvent(
                            ipvSessionItem,
                            clientOAuthSessionItem,
                            matchedProfile.get(),
                            gpg45Scores,
                            credentials,
                            ipAddress));
            ipvSessionItem.setVot(VOT_P2);
            ipvSessionService.updateIpvSession(ipvSessionItem);

            LOGGER.info(
                    new StringMapMessage()
                            .with("lambdaResult", "A GPG45 profile has been met")
                            .with("journeyResponse", JOURNEY_END));
            return JOURNEY_END;
        } else {
            LOGGER.info(
                    new StringMapMessage()
                            .with("lambdaResult", "No GPG45 profiles have been met")
                            .with("journeyResponse", JOURNEY_NEXT));

            return JOURNEY_NEXT;
        }
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
    private Optional<JourneyResponse> getJourneyResponseForFailWithNoCi(
            IpvSessionItem ipvSessionItem, String userId)
            throws NoVisitedCriFoundException, ParseException {
        VisitedCredentialIssuerDetailsDto lastVisitedCri =
                ipvSessionItem.getVisitedCredentialIssuerDetails().stream()
                        .reduce((first, second) -> second)
                        .orElseThrow(NoVisitedCriFoundException::new);

        Optional<Boolean> lastVisitedCriVcStatus =
                userIdentityService.getVCSuccessStatus(userId, lastVisitedCri.getCriId());

        if (lastVisitedCriVcStatus.isPresent()
                && Boolean.FALSE.equals(lastVisitedCriVcStatus.get())) {
            // Handle scenario where VCs without CIs should be redirected
            StringMapMessage message = new StringMapMessage();
            message.with(
                            LOG_MESSAGE_DESCRIPTION.getFieldName(),
                            "Returning fail-with-no-ci response")
                    .with(LOG_ERROR_JOURNEY_RESPONSE.getFieldName(), JOURNEY_FAIL_WITH_NO_CI)
                    .with("lastVisitedCri", lastVisitedCri.getCriId())
                    .with("lastVisitedCriVcStatus", lastVisitedCriVcStatus.get());
            LOGGER.info(message);
            return Optional.of(JOURNEY_FAIL_WITH_NO_CI);
        }
        return Optional.empty();
    }
}
