package uk.gov.di.ipv.core.evaluategpg45scores;

import com.amazonaws.services.lambda.runtime.Context;
import com.amazonaws.services.lambda.runtime.RequestHandler;
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
import uk.gov.di.ipv.core.library.config.CoreFeatureFlag;
import uk.gov.di.ipv.core.library.domain.ErrorResponse;
import uk.gov.di.ipv.core.library.domain.JourneyErrorResponse;
import uk.gov.di.ipv.core.library.domain.JourneyRequest;
import uk.gov.di.ipv.core.library.domain.JourneyResponse;
import uk.gov.di.ipv.core.library.domain.ProfileType;
import uk.gov.di.ipv.core.library.enums.Vot;
import uk.gov.di.ipv.core.library.exceptions.CredentialParseException;
import uk.gov.di.ipv.core.library.exceptions.HttpResponseExceptionWithErrorBody;
import uk.gov.di.ipv.core.library.exceptions.SqsException;
import uk.gov.di.ipv.core.library.gpg45.Gpg45ProfileEvaluator;
import uk.gov.di.ipv.core.library.gpg45.Gpg45Scores;
import uk.gov.di.ipv.core.library.gpg45.enums.Gpg45Profile;
import uk.gov.di.ipv.core.library.gpg45.exception.UnknownEvidenceTypeException;
import uk.gov.di.ipv.core.library.helpers.LogHelper;
import uk.gov.di.ipv.core.library.helpers.RequestHelper;
import uk.gov.di.ipv.core.library.journeyuris.JourneyUris;
import uk.gov.di.ipv.core.library.persistence.item.ClientOAuthSessionItem;
import uk.gov.di.ipv.core.library.persistence.item.IpvSessionItem;
import uk.gov.di.ipv.core.library.persistence.item.VcStoreItem;
import uk.gov.di.ipv.core.library.service.AuditService;
import uk.gov.di.ipv.core.library.service.ClientOAuthSessionDetailsService;
import uk.gov.di.ipv.core.library.service.ConfigService;
import uk.gov.di.ipv.core.library.service.IpvSessionService;
import uk.gov.di.ipv.core.library.service.UserIdentityService;
import uk.gov.di.ipv.core.library.verifiablecredential.helpers.VcHelper;
import uk.gov.di.ipv.core.library.verifiablecredential.service.VerifiableCredentialService;

import java.text.ParseException;
import java.util.List;
import java.util.Map;
import java.util.Optional;

import static uk.gov.di.ipv.core.library.domain.CriConstants.HMRC_MIGRATION_CRI;
import static uk.gov.di.ipv.core.library.helpers.LogHelper.LogField.LOG_JOURNEY_RESPONSE;
import static uk.gov.di.ipv.core.library.helpers.LogHelper.LogField.LOG_LAMBDA_RESULT;
import static uk.gov.di.ipv.core.library.journeyuris.JourneyUris.JOURNEY_ERROR_PATH;
import static uk.gov.di.ipv.core.library.journeyuris.JourneyUris.JOURNEY_MET_PATH;
import static uk.gov.di.ipv.core.library.journeyuris.JourneyUris.JOURNEY_UNMET_PATH;

/** Evaluate the gathered credentials against a desired GPG45 profile. */
public class EvaluateGpg45ScoresHandler
        implements RequestHandler<JourneyRequest, Map<String, Object>> {
    private static final JourneyResponse JOURNEY_MET = new JourneyResponse(JOURNEY_MET_PATH);
    private static final JourneyResponse JOURNEY_UNMET = new JourneyResponse(JOURNEY_UNMET_PATH);
    private static final JourneyResponse JOURNEY_VCS_NOT_CORRELATED =
            new JourneyResponse(JourneyUris.JOURNEY_VCS_NOT_CORRELATED);
    private static final Logger LOGGER = LogManager.getLogger();
    private final UserIdentityService userIdentityService;
    private final IpvSessionService ipvSessionService;
    private final Gpg45ProfileEvaluator gpg45ProfileEvaluator;
    private final ConfigService configService;
    private final AuditService auditService;
    private final ClientOAuthSessionDetailsService clientOAuthSessionDetailsService;
    private final VerifiableCredentialService verifiableCredentialService;

    @SuppressWarnings("unused") // Used by tests through injection
    public EvaluateGpg45ScoresHandler(
            UserIdentityService userIdentityService,
            IpvSessionService ipvSessionService,
            Gpg45ProfileEvaluator gpg45ProfileEvaluator,
            ConfigService configService,
            AuditService auditService,
            ClientOAuthSessionDetailsService clientOAuthSessionDetailsService,
            VerifiableCredentialService verifiableCredentialService) {
        this.userIdentityService = userIdentityService;
        this.ipvSessionService = ipvSessionService;
        this.gpg45ProfileEvaluator = gpg45ProfileEvaluator;
        this.configService = configService;
        this.auditService = auditService;
        this.clientOAuthSessionDetailsService = clientOAuthSessionDetailsService;
        this.verifiableCredentialService = verifiableCredentialService;
        VcHelper.setConfigService(this.configService);
    }

    @SuppressWarnings("unused") // Used by AWS
    @ExcludeFromGeneratedCoverageReport
    public EvaluateGpg45ScoresHandler() {
        this.configService = new ConfigService();
        this.userIdentityService = new UserIdentityService(configService);
        this.ipvSessionService = new IpvSessionService(configService);
        this.gpg45ProfileEvaluator = new Gpg45ProfileEvaluator();
        this.auditService = new AuditService(AuditService.getDefaultSqsClient(), configService);
        this.clientOAuthSessionDetailsService = new ClientOAuthSessionDetailsService(configService);
        this.verifiableCredentialService = new VerifiableCredentialService(configService);
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

            List<VcStoreItem> allVcStoreItems = verifiableCredentialService.getVcStoreItems(userId);
            List<VcStoreItem> vcStoreItems =
                    VcHelper.filterVCBasedOnProfileType(allVcStoreItems, ProfileType.GPG45);

            List<SignedJWT> credentials =
                    gpg45ProfileEvaluator.parseCredentials(
                            userIdentityService.getIdentityCredentials(vcStoreItems));

            if (!userIdentityService.areVCsCorrelated(vcStoreItems)) {
                return JOURNEY_VCS_NOT_CORRELATED.toObjectMap();
            }

            boolean hasMatchingGpg45Profile =
                    checkForMatchingGpg45Profile(
                            vcStoreItems,
                            ipvSessionItem,
                            clientOAuthSessionItem,
                            credentials,
                            ipAddress);

            if (configService.enabled(CoreFeatureFlag.INHERITED_IDENTITY)
                    && hasMatchingGpg45Profile) {
                for (VcStoreItem vcStoreItem : allVcStoreItems) {

                    if (vcStoreItem.getCredentialIssuer().equals(HMRC_MIGRATION_CRI)) {
                        verifiableCredentialService.deleteVcStoreItem(
                                vcStoreItem.getUserId(), vcStoreItem.getCredentialIssuer());
                    }
                }
            }
            return hasMatchingGpg45Profile
                    ? JOURNEY_MET.toObjectMap()
                    : JOURNEY_UNMET.toObjectMap();
        } catch (HttpResponseExceptionWithErrorBody e) {
            LOGGER.error(LogHelper.buildErrorMessage("Received HTTP response exception", e));
            return new JourneyErrorResponse(
                            JOURNEY_ERROR_PATH, e.getResponseCode(), e.getErrorResponse())
                    .toObjectMap();
        } catch (ParseException e) {
            LOGGER.error(
                    LogHelper.buildErrorMessage(
                            "Unable to parse GPG45 scores from existing credentials", e));
            return buildJourneyErrorResponse(ErrorResponse.FAILED_TO_PARSE_ISSUED_CREDENTIALS);
        } catch (UnknownEvidenceTypeException e) {
            LOGGER.error(LogHelper.buildErrorMessage("Unable to determine type of credential", e));
            return buildJourneyErrorResponse(ErrorResponse.FAILED_TO_DETERMINE_CREDENTIAL_TYPE);
        } catch (SqsException e) {
            LOGGER.error(LogHelper.buildErrorMessage("Failed to send audit event to SQS queue", e));
            return buildJourneyErrorResponse(ErrorResponse.FAILED_TO_SEND_AUDIT_EVENT);
        } catch (CredentialParseException e) {
            LOGGER.error(LogHelper.buildErrorMessage("Unable to parse credential", e));
            return buildJourneyErrorResponse(
                    ErrorResponse.FAILED_TO_PARSE_SUCCESSFUL_VC_STORE_ITEMS);
        }
    }

    private Map<String, Object> buildJourneyErrorResponse(ErrorResponse errorResponse) {
        return new JourneyErrorResponse(
                        JOURNEY_ERROR_PATH, HttpStatus.SC_INTERNAL_SERVER_ERROR, errorResponse)
                .toObjectMap();
    }

    @Tracing
    private Boolean checkForMatchingGpg45Profile(
            List<VcStoreItem> vcStoreItems,
            IpvSessionItem ipvSessionItem,
            ClientOAuthSessionItem clientOAuthSessionItem,
            List<SignedJWT> credentials,
            String ipAddress)
            throws UnknownEvidenceTypeException, ParseException, SqsException {
        if (!userIdentityService.checkRequiresAdditionalEvidence(vcStoreItems)) {
            Gpg45Scores gpg45Scores = gpg45ProfileEvaluator.buildScore(credentials);
            Optional<Gpg45Profile> matchedProfile =
                    gpg45ProfileEvaluator.getFirstMatchingProfile(
                            gpg45Scores, Vot.P2.getSupportedGpg45Profiles());

            if (matchedProfile.isPresent()) {

                auditService.sendAuditEvent(
                        buildProfileMatchedAuditEvent(
                                ipvSessionItem,
                                clientOAuthSessionItem,
                                matchedProfile.get(),
                                gpg45Scores,
                                credentials,
                                ipAddress));
                ipvSessionItem.setVot(Vot.P2);
                ipvSessionService.updateIpvSession(ipvSessionItem);

                logLambdaResponse("A GPG45 profile has been met", JOURNEY_MET);
                return true;
            }
        }
        logLambdaResponse("No GPG45 profiles have been met", JOURNEY_UNMET);
        return false;
    }

    private void logLambdaResponse(String lambdaResult, JourneyResponse journeyResponse) {
        var message =
                new StringMapMessage()
                        .with(LOG_LAMBDA_RESULT.getFieldName(), lambdaResult)
                        .with(LOG_JOURNEY_RESPONSE.getFieldName(), journeyResponse);
        LOGGER.info(message);
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
                        gpg45Profile,
                        gpg45Scores,
                        VcHelper.extractTxnIdsFromCredentials(credentials)));
    }
}
