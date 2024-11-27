package uk.gov.di.ipv.core.checkreverificationidentity;

import com.amazonaws.services.lambda.runtime.Context;
import com.amazonaws.services.lambda.runtime.RequestHandler;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import software.amazon.lambda.powertools.logging.Logging;
import software.amazon.lambda.powertools.tracing.Tracing;
import uk.gov.di.ipv.core.library.annotations.ExcludeFromGeneratedCoverageReport;
import uk.gov.di.ipv.core.library.domain.JourneyErrorResponse;
import uk.gov.di.ipv.core.library.domain.JourneyRequest;
import uk.gov.di.ipv.core.library.domain.JourneyResponse;
import uk.gov.di.ipv.core.library.domain.VerifiableCredential;
import uk.gov.di.ipv.core.library.enums.Vot;
import uk.gov.di.ipv.core.library.exception.EvcsServiceException;
import uk.gov.di.ipv.core.library.exceptions.CredentialParseException;
import uk.gov.di.ipv.core.library.exceptions.HttpResponseExceptionWithErrorBody;
import uk.gov.di.ipv.core.library.exceptions.IpvSessionNotFoundException;
import uk.gov.di.ipv.core.library.gpg45.Gpg45ProfileEvaluator;
import uk.gov.di.ipv.core.library.helpers.LogHelper;
import uk.gov.di.ipv.core.library.helpers.RequestHelper;
import uk.gov.di.ipv.core.library.service.ClientOAuthSessionDetailsService;
import uk.gov.di.ipv.core.library.service.ConfigService;
import uk.gov.di.ipv.core.library.service.EvcsService;
import uk.gov.di.ipv.core.library.service.IpvSessionService;
import uk.gov.di.ipv.core.library.service.UserIdentityService;
import uk.gov.di.ipv.core.library.verifiablecredential.helpers.VcHelper;

import java.text.ParseException;
import java.util.List;
import java.util.Map;

import static com.nimbusds.oauth2.sdk.http.HTTPResponse.SC_NOT_FOUND;
import static com.nimbusds.oauth2.sdk.http.HTTPResponse.SC_SERVER_ERROR;
import static uk.gov.di.ipv.core.library.domain.ErrorResponse.FAILED_TO_PARSE_ISSUED_CREDENTIALS;
import static uk.gov.di.ipv.core.library.domain.ErrorResponse.FAILED_TO_PARSE_SUCCESSFUL_VC_STORE_ITEMS;
import static uk.gov.di.ipv.core.library.domain.ErrorResponse.IPV_SESSION_NOT_FOUND;
import static uk.gov.di.ipv.core.library.domain.ProfileType.GPG45;
import static uk.gov.di.ipv.core.library.domain.ProfileType.OPERATIONAL_HMRC;
import static uk.gov.di.ipv.core.library.domain.ReverificationFailureCode.NO_IDENTITY_AVAILABLE;
import static uk.gov.di.ipv.core.library.domain.VocabConstants.VOT_CLAIM_NAME;
import static uk.gov.di.ipv.core.library.enums.EvcsVCState.CURRENT;
import static uk.gov.di.ipv.core.library.enums.Vot.SUPPORTED_VOTS_BY_DESCENDING_STRENGTH;
import static uk.gov.di.ipv.core.library.helpers.LogHelper.LogField.LOG_PROFILE;
import static uk.gov.di.ipv.core.library.helpers.LogHelper.LogField.LOG_VOT;
import static uk.gov.di.ipv.core.library.helpers.RequestHelper.getIpvSessionId;
import static uk.gov.di.ipv.core.library.journeys.JourneyUris.JOURNEY_ERROR_PATH;
import static uk.gov.di.ipv.core.library.journeys.JourneyUris.JOURNEY_FOUND;
import static uk.gov.di.ipv.core.library.journeys.JourneyUris.JOURNEY_NOT_FOUND_PATH;

public class CheckReverificationIdentityHandler
        implements RequestHandler<JourneyRequest, Map<String, Object>> {
    private static final Logger LOGGER = LogManager.getLogger();
    private static final Map<String, Object> NOT_FOUND_RESPONSE =
            new JourneyResponse(JOURNEY_NOT_FOUND_PATH).toObjectMap();
    private static final Map<String, Object> FOUND_RESPONSE =
            new JourneyResponse(JOURNEY_FOUND).toObjectMap();
    private final ConfigService configService;
    private final IpvSessionService ipvSessionService;
    private final ClientOAuthSessionDetailsService clientSessionService;
    private final EvcsService evcsService;
    private final UserIdentityService userIdentityService;
    private final Gpg45ProfileEvaluator gpg45ProfileEvaluator;

    public CheckReverificationIdentityHandler(
            ConfigService configService,
            IpvSessionService ipvSessionService,
            ClientOAuthSessionDetailsService clientOAuthSessionDetailsService,
            EvcsService evcsService,
            UserIdentityService userIdentityService,
            Gpg45ProfileEvaluator gpg45ProfileEvaluator) {
        this.configService = configService;
        this.ipvSessionService = ipvSessionService;
        this.clientSessionService = clientOAuthSessionDetailsService;
        this.evcsService = evcsService;
        this.userIdentityService = userIdentityService;
        this.gpg45ProfileEvaluator = gpg45ProfileEvaluator;
    }

    @ExcludeFromGeneratedCoverageReport
    public CheckReverificationIdentityHandler() {
        this(ConfigService.create());
    }

    @ExcludeFromGeneratedCoverageReport
    public CheckReverificationIdentityHandler(ConfigService configService) {
        this.configService = ConfigService.create();
        this.ipvSessionService = new IpvSessionService(configService);
        this.clientSessionService = new ClientOAuthSessionDetailsService(configService);
        this.evcsService = new EvcsService(configService);
        this.userIdentityService = new UserIdentityService(configService);
        this.gpg45ProfileEvaluator = new Gpg45ProfileEvaluator();
    }

    @Tracing
    @Logging(clearState = true)
    @Override
    public Map<String, Object> handleRequest(JourneyRequest request, Context context) {
        LogHelper.attachComponentId(configService);
        configService.setFeatureSet(RequestHelper.getFeatureSet(request));

        try {
            var ipvSessionId = getIpvSessionId(request);
            LogHelper.attachIpvSessionIdToLogs(ipvSessionId);
            var ipvSession = ipvSessionService.getIpvSession(ipvSessionId);
            LogHelper.attachClientSessionIdToLogs(ipvSession.getClientOAuthSessionId());
            var clientOAuthSession =
                    clientSessionService.getClientOAuthSession(
                            ipvSession.getClientOAuthSessionId());
            LogHelper.attachClientIdToLogs(clientOAuthSession.getClientId());
            LogHelper.attachGovukSigninJourneyIdToLogs(
                    clientOAuthSession.getGovukSigninJourneyId());

            var vcs =
                    evcsService.getVerifiableCredentials(
                            clientOAuthSession.getUserId(),
                            clientOAuthSession.getEvcsAccessToken(),
                            CURRENT);

            if (!vcsContainIdentity(vcs)) {
                ipvSession.setFailureCode(NO_IDENTITY_AVAILABLE);
                ipvSessionService.updateIpvSession(ipvSession);
                return NOT_FOUND_RESPONSE;
            }

            return FOUND_RESPONSE;

        } catch (HttpResponseExceptionWithErrorBody | EvcsServiceException e) {
            LOGGER.error(LogHelper.buildErrorMessage(e.getErrorResponse()));
            return new JourneyErrorResponse(
                            JOURNEY_ERROR_PATH, e.getResponseCode(), e.getErrorResponse())
                    .toObjectMap();
        } catch (IpvSessionNotFoundException e) {
            LOGGER.error(LogHelper.buildErrorMessage("IPV session not found", e));
            return new JourneyErrorResponse(JOURNEY_ERROR_PATH, SC_NOT_FOUND, IPV_SESSION_NOT_FOUND)
                    .toObjectMap();
        } catch (CredentialParseException e) {
            LOGGER.error(LogHelper.buildErrorMessage("Failed to parse credentials", e));
            return new JourneyErrorResponse(
                            JOURNEY_ERROR_PATH,
                            SC_SERVER_ERROR,
                            FAILED_TO_PARSE_SUCCESSFUL_VC_STORE_ITEMS)
                    .toObjectMap();
        } catch (ParseException e) {
            LOGGER.error(LogHelper.buildErrorMessage("Failed to get VOT from operational VC", e));
            return new JourneyErrorResponse(
                            JOURNEY_ERROR_PATH, SC_SERVER_ERROR, FAILED_TO_PARSE_ISSUED_CREDENTIALS)
                    .toObjectMap();
        } catch (Exception e) {
            LOGGER.error(LogHelper.buildErrorMessage("Unhandled lambda exception", e));
            throw e;
        }
    }

    private boolean vcsContainIdentity(List<VerifiableCredential> vcs)
            throws ParseException, HttpResponseExceptionWithErrorBody {
        var gpg45Vcs = VcHelper.filterVCBasedOnProfileType(vcs, GPG45);
        var gpg45Scores = gpg45ProfileEvaluator.buildScore(gpg45Vcs);
        var gpg45VcsCorrelated = userIdentityService.areVcsCorrelated(gpg45Vcs);
        var operationalVcs = VcHelper.filterVCBasedOnProfileType(vcs, OPERATIONAL_HMRC);

        for (var vot : SUPPORTED_VOTS_BY_DESCENDING_STRENGTH) {
            if (GPG45.equals(vot.getProfileType()) && gpg45VcsCorrelated) {
                var matchedProfile =
                        gpg45ProfileEvaluator.getFirstMatchingProfile(
                                gpg45Scores, vot.getSupportedGpg45Profiles());
                if (matchedProfile.isPresent()) {
                    LOGGER.info(
                            LogHelper.buildLogMessage("Identity for reverification found")
                                    .with(LOG_VOT.getFieldName(), vot)
                                    .with(LOG_PROFILE.getFieldName(), matchedProfile.get()));
                    return true;
                }
            }
            if (OPERATIONAL_HMRC.equals(vot.getProfileType())
                    && vcsContainOperationalVot(operationalVcs, vot)) {
                LOGGER.info(
                        LogHelper.buildLogMessage("Identity for reverification found")
                                .with(LOG_VOT.getFieldName(), vot));
                return true;
            }
        }
        LOGGER.info(LogHelper.buildLogMessage("No identity for reverification found"));
        return false;
    }

    private boolean vcsContainOperationalVot(List<VerifiableCredential> vcs, Vot vot)
            throws ParseException {
        for (var vc : vcs) {
            var credentialVot = vc.getClaimsSet().getStringClaim(VOT_CLAIM_NAME);
            if (vot.name().equals(credentialVot)) {
                return true;
            }
        }
        return false;
    }
}
