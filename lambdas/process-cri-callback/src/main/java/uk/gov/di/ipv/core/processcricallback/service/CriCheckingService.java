package uk.gov.di.ipv.core.processcricallback.service;

import com.nimbusds.oauth2.sdk.OAuth2Error;
import com.nimbusds.oauth2.sdk.http.HTTPResponse;
import com.nimbusds.oauth2.sdk.util.StringUtils;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import uk.gov.di.ipv.core.library.annotations.ExcludeFromGeneratedCoverageReport;
import uk.gov.di.ipv.core.library.auditing.AuditEvent;
import uk.gov.di.ipv.core.library.auditing.AuditEventTypes;
import uk.gov.di.ipv.core.library.auditing.AuditEventUser;
import uk.gov.di.ipv.core.library.auditing.extension.AuditExtensionErrorParams;
import uk.gov.di.ipv.core.library.auditing.restricted.AuditRestrictedDeviceInformation;
import uk.gov.di.ipv.core.library.cimit.exception.CiRetrievalException;
import uk.gov.di.ipv.core.library.config.ConfigurationVariable;
import uk.gov.di.ipv.core.library.domain.ErrorResponse;
import uk.gov.di.ipv.core.library.domain.JourneyResponse;
import uk.gov.di.ipv.core.library.domain.ScopeConstants;
import uk.gov.di.ipv.core.library.domain.VerifiableCredential;
import uk.gov.di.ipv.core.library.dto.CriCallbackRequest;
import uk.gov.di.ipv.core.library.exceptions.ConfigException;
import uk.gov.di.ipv.core.library.exceptions.HttpResponseExceptionWithErrorBody;
import uk.gov.di.ipv.core.library.exceptions.SqsException;
import uk.gov.di.ipv.core.library.exceptions.VerifiableCredentialException;
import uk.gov.di.ipv.core.library.helpers.LogHelper;
import uk.gov.di.ipv.core.library.journeyuris.JourneyUris;
import uk.gov.di.ipv.core.library.persistence.item.ClientOAuthSessionItem;
import uk.gov.di.ipv.core.library.persistence.item.CriOAuthSessionItem;
import uk.gov.di.ipv.core.library.persistence.item.IpvSessionItem;
import uk.gov.di.ipv.core.library.service.AuditService;
import uk.gov.di.ipv.core.library.service.CiMitService;
import uk.gov.di.ipv.core.library.service.CiMitUtilityService;
import uk.gov.di.ipv.core.library.service.ConfigService;
import uk.gov.di.ipv.core.library.service.UserIdentityService;
import uk.gov.di.ipv.core.library.verifiablecredential.domain.VerifiableCredentialResponse;
import uk.gov.di.ipv.core.library.verifiablecredential.helpers.VcHelper;
import uk.gov.di.ipv.core.library.verifiablecredential.service.SessionCredentialsService;
import uk.gov.di.ipv.core.processcricallback.exception.InvalidCriCallbackRequestException;

import java.util.Arrays;
import java.util.List;
import java.util.Objects;

import static uk.gov.di.ipv.core.library.domain.ErrorResponse.FAILED_TO_VALIDATE_VERIFIABLE_CREDENTIAL_RESPONSE;
import static uk.gov.di.ipv.core.library.journeyuris.JourneyUris.JOURNEY_ACCESS_DENIED_PATH;
import static uk.gov.di.ipv.core.library.journeyuris.JourneyUris.JOURNEY_ERROR_PATH;
import static uk.gov.di.ipv.core.library.journeyuris.JourneyUris.JOURNEY_FAIL_WITH_NO_CI_PATH;
import static uk.gov.di.ipv.core.library.journeyuris.JourneyUris.JOURNEY_NEXT_PATH;
import static uk.gov.di.ipv.core.library.journeyuris.JourneyUris.JOURNEY_TEMPORARILY_UNAVAILABLE_PATH;

public class CriCheckingService {
    private static final Logger LOGGER = LogManager.getLogger();
    private static final JourneyResponse JOURNEY_NEXT = new JourneyResponse(JOURNEY_NEXT_PATH);
    private static final JourneyResponse JOURNEY_VCS_NOT_CORRELATED =
            new JourneyResponse(JourneyUris.JOURNEY_VCS_NOT_CORRELATED);
    private static final JourneyResponse JOURNEY_FAIL_WITH_NO_CI =
            new JourneyResponse(JOURNEY_FAIL_WITH_NO_CI_PATH);
    private static final JourneyResponse JOURNEY_ACCESS_DENIED =
            new JourneyResponse(JOURNEY_ACCESS_DENIED_PATH);
    private static final JourneyResponse JOURNEY_TEMPORARILY_UNAVAILABLE =
            new JourneyResponse(JOURNEY_TEMPORARILY_UNAVAILABLE_PATH);
    private static final JourneyResponse JOURNEY_ERROR = new JourneyResponse(JOURNEY_ERROR_PATH);
    private static final JourneyResponse JOURNEY_INVALID_REQUEST =
            new JourneyResponse(JourneyUris.JOURNEY_INVALID_REQUEST_PATH);

    private static final List<String> ALLOWED_OAUTH_ERROR_CODES =
            Arrays.asList(
                    OAuth2Error.INVALID_REQUEST_CODE,
                    OAuth2Error.UNAUTHORIZED_CLIENT_CODE,
                    OAuth2Error.ACCESS_DENIED_CODE,
                    OAuth2Error.UNSUPPORTED_RESPONSE_TYPE_CODE,
                    OAuth2Error.INVALID_SCOPE_CODE,
                    OAuth2Error.SERVER_ERROR_CODE,
                    OAuth2Error.TEMPORARILY_UNAVAILABLE_CODE);
    private final UserIdentityService userIdentityService;
    private final AuditService auditService;
    private final CiMitService ciMitService;
    private final CiMitUtilityService ciMitUtilityService;
    private final ConfigService configService;
    private final SessionCredentialsService sessionCredentialsService;

    @ExcludeFromGeneratedCoverageReport
    public CriCheckingService(
            ConfigService configService,
            AuditService auditService,
            UserIdentityService userIdentityService,
            CiMitService ciMitService,
            CiMitUtilityService ciMitUtilityService,
            SessionCredentialsService sessionCredentialsService) {
        this.configService = configService;
        this.auditService = auditService;
        this.userIdentityService = userIdentityService;
        this.ciMitService = ciMitService;
        this.ciMitUtilityService = ciMitUtilityService;
        this.sessionCredentialsService = sessionCredentialsService;
    }

    public JourneyResponse handleCallbackError(
            CriCallbackRequest callbackRequest, ClientOAuthSessionItem clientOAuthSessionItem)
            throws SqsException {
        var ipAddress = callbackRequest.getIpAddress();
        var deviceInformation = callbackRequest.getDeviceInformation();
        var errorCode = callbackRequest.getError();
        var errorDescription =
                Objects.toString(
                        callbackRequest.getErrorDescription(), "No error description provided");
        var userId = clientOAuthSessionItem.getUserId();
        var govukSigninJourneyId = clientOAuthSessionItem.getGovukSigninJourneyId();

        var auditEventUser =
                new AuditEventUser(
                        userId, callbackRequest.getIpvSessionId(), govukSigninJourneyId, ipAddress);

        AuditExtensionErrorParams extensions =
                new AuditExtensionErrorParams.Builder()
                        .setErrorCode(errorCode)
                        .setErrorDescription(errorDescription)
                        .build();

        auditService.sendAuditEvent(
                AuditEvent.createWithDeviceInformation(
                        AuditEventTypes.IPV_CRI_AUTH_RESPONSE_RECEIVED,
                        configService.getSsmParameter(ConfigurationVariable.COMPONENT_ID),
                        auditEventUser,
                        extensions,
                        new AuditRestrictedDeviceInformation(deviceInformation)));

        if (!ALLOWED_OAUTH_ERROR_CODES.contains(errorCode)) {
            LOGGER.warn(LogHelper.buildLogMessage("Unknown Oauth error code received"));
        }

        LOGGER.error(
                LogHelper.buildErrorMessage(
                        "OAuth error received from CRI", errorDescription, errorCode));

        return (switch (errorCode) {
            case OAuth2Error.ACCESS_DENIED_CODE -> JOURNEY_ACCESS_DENIED;
            case OAuth2Error.TEMPORARILY_UNAVAILABLE_CODE -> JOURNEY_TEMPORARILY_UNAVAILABLE;
            case OAuth2Error.INVALID_REQUEST_CODE -> JOURNEY_INVALID_REQUEST;
            default -> JOURNEY_ERROR;
        });
    }

    public void validateSessionIds(CriCallbackRequest callbackRequest)
            throws InvalidCriCallbackRequestException {
        var ipvSessionId = callbackRequest.getIpvSessionId();
        var criOAuthSessionId = callbackRequest.getState();

        if (StringUtils.isBlank(ipvSessionId)) {
            if (!StringUtils.isBlank(criOAuthSessionId)) {
                throw new InvalidCriCallbackRequestException(
                        ErrorResponse.NO_IPV_FOR_CRI_OAUTH_SESSION);
            }
            throw new InvalidCriCallbackRequestException(ErrorResponse.MISSING_OAUTH_STATE);
        }
    }

    public void validateCallbackRequest(
            CriCallbackRequest callbackRequest, CriOAuthSessionItem criOAuthSessionItem)
            throws InvalidCriCallbackRequestException {
        var ipvSessionId = callbackRequest.getIpvSessionId();
        var state = callbackRequest.getState();
        var authorisationCode = callbackRequest.getAuthorizationCode();

        if (StringUtils.isBlank(authorisationCode)) {
            throw new InvalidCriCallbackRequestException(ErrorResponse.MISSING_AUTHORIZATION_CODE);
        }
        if (StringUtils.isBlank(ipvSessionId)) {
            throw new InvalidCriCallbackRequestException(ErrorResponse.MISSING_IPV_SESSION_ID);
        }
        if (StringUtils.isBlank(state)) {
            throw new InvalidCriCallbackRequestException(ErrorResponse.MISSING_OAUTH_STATE);
        }
        if (criOAuthSessionItem == null
                || !state.equals(criOAuthSessionItem.getCriOAuthSessionId())) {
            throw new InvalidCriCallbackRequestException(ErrorResponse.INVALID_OAUTH_STATE);
        }
        try {
            var cri = callbackRequest.getCredentialIssuer();
            if (cri == null) {
                throw new InvalidCriCallbackRequestException(
                        ErrorResponse.MISSING_CREDENTIAL_ISSUER_ID);
            }

        } catch (IllegalArgumentException e) {
            throw new InvalidCriCallbackRequestException(
                    ErrorResponse.INVALID_CREDENTIAL_ISSUER_ID);
        }
    }

    public void validateOAuthForError(
            CriCallbackRequest callbackRequest,
            CriOAuthSessionItem criOAuthSessionItem,
            IpvSessionItem ipvSessionItem)
            throws InvalidCriCallbackRequestException {
        if (ipvSessionItem.getCriOAuthSessionId() == null
                || criOAuthSessionItem == null
                || criOAuthSessionItem.getCriId() == null
                || !criOAuthSessionItem
                        .getCriId()
                        .equals(callbackRequest.getCredentialIssuer().getId())) {
            throw new InvalidCriCallbackRequestException(ErrorResponse.INVALID_OAUTH_STATE);
        }
    }

    public void validatePendingVcResponse(
            VerifiableCredentialResponse vcResponse, ClientOAuthSessionItem clientOAuthSessionItem)
            throws VerifiableCredentialException {
        var userId = clientOAuthSessionItem.getUserId();

        if (!vcResponse.getUserId().equals(userId)) {
            throw new VerifiableCredentialException(
                    HTTPResponse.SC_SERVER_ERROR,
                    FAILED_TO_VALIDATE_VERIFIABLE_CREDENTIAL_RESPONSE);
        }
    }

    public JourneyResponse checkVcResponse(
            List<VerifiableCredential> newVcs,
            CriCallbackRequest callbackRequest,
            ClientOAuthSessionItem clientOAuthSessionItem,
            String ipvSessionId)
            throws CiRetrievalException, ConfigException, HttpResponseExceptionWithErrorBody,
                    VerifiableCredentialException {

        var scopeClaims = clientOAuthSessionItem.getScopeClaims();
        if (!scopeClaims.contains(ScopeConstants.REVERIFICATION)) {
            var cis =
                    ciMitService.getContraIndicators(
                            clientOAuthSessionItem.getUserId(),
                            clientOAuthSessionItem.getGovukSigninJourneyId(),
                            callbackRequest.getIpAddress());

            // Check CI levels against the lowest confidence identity requested so we don't send the
            // user on an unnecessary mitigation journey.
            var lowestConfidenceRequested =
                    clientOAuthSessionItem.getLowestStrengthRequestedGpg45Vot(configService);
            var journeyResponse =
                    ciMitUtilityService.getMitigationJourneyIfBreaching(
                            cis, lowestConfidenceRequested);
            if (journeyResponse.isPresent()) {
                return journeyResponse.get();
            }
        }

        if (!userIdentityService.areVcsCorrelated(
                sessionCredentialsService.getCredentials(
                        ipvSessionId, clientOAuthSessionItem.getUserId()))) {
            return JOURNEY_VCS_NOT_CORRELATED;
        }

        for (var vc : newVcs) {
            if (!VcHelper.isSuccessfulVc(vc)) {
                return JOURNEY_FAIL_WITH_NO_CI;
            }
        }

        return JOURNEY_NEXT;
    }
}
