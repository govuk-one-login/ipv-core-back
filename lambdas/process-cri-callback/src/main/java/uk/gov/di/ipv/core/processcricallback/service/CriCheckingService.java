package uk.gov.di.ipv.core.processcricallback.service;

import com.nimbusds.oauth2.sdk.OAuth2Error;
import com.nimbusds.oauth2.sdk.http.HTTPResponse;
import com.nimbusds.oauth2.sdk.util.StringUtils;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import software.amazon.awssdk.http.HttpStatusCode;
import uk.gov.di.ipv.core.library.annotations.ExcludeFromGeneratedCoverageReport;
import uk.gov.di.ipv.core.library.auditing.AuditEvent;
import uk.gov.di.ipv.core.library.auditing.AuditEventTypes;
import uk.gov.di.ipv.core.library.auditing.AuditEventUser;
import uk.gov.di.ipv.core.library.auditing.extension.AuditExtensionErrorParams;
import uk.gov.di.ipv.core.library.auditing.restricted.AuditRestrictedDeviceInformation;
import uk.gov.di.ipv.core.library.cimit.exception.CiRetrievalException;
import uk.gov.di.ipv.core.library.cimit.service.CimitService;
import uk.gov.di.ipv.core.library.config.ConfigurationVariable;
import uk.gov.di.ipv.core.library.domain.Cri;
import uk.gov.di.ipv.core.library.domain.ErrorResponse;
import uk.gov.di.ipv.core.library.domain.JourneyResponse;
import uk.gov.di.ipv.core.library.domain.ReverificationFailureCode;
import uk.gov.di.ipv.core.library.domain.ScopeConstants;
import uk.gov.di.ipv.core.library.domain.VerifiableCredential;
import uk.gov.di.ipv.core.library.dto.CriCallbackRequest;
import uk.gov.di.ipv.core.library.exceptions.CiExtractionException;
import uk.gov.di.ipv.core.library.exceptions.ConfigException;
import uk.gov.di.ipv.core.library.exceptions.HttpResponseExceptionWithErrorBody;
import uk.gov.di.ipv.core.library.exceptions.VerifiableCredentialException;
import uk.gov.di.ipv.core.library.helpers.LogHelper;
import uk.gov.di.ipv.core.library.journeys.JourneyUris;
import uk.gov.di.ipv.core.library.persistence.item.ClientOAuthSessionItem;
import uk.gov.di.ipv.core.library.persistence.item.CriOAuthSessionItem;
import uk.gov.di.ipv.core.library.persistence.item.IpvSessionItem;
import uk.gov.di.ipv.core.library.service.AuditService;
import uk.gov.di.ipv.core.library.service.CimitUtilityService;
import uk.gov.di.ipv.core.library.service.ConfigService;
import uk.gov.di.ipv.core.library.service.IpvSessionService;
import uk.gov.di.ipv.core.library.useridentity.service.UserIdentityService;
import uk.gov.di.ipv.core.library.verifiablecredential.domain.VerifiableCredentialResponse;
import uk.gov.di.ipv.core.library.verifiablecredential.helpers.VcHelper;
import uk.gov.di.ipv.core.processcricallback.exception.InvalidCriCallbackRequestException;
import uk.gov.di.model.IdentityCheckSubject;

import java.security.InvalidParameterException;
import java.util.Arrays;
import java.util.List;
import java.util.Objects;
import java.util.Optional;

import static uk.gov.di.ipv.core.library.config.CoreFeatureFlag.DL_AUTH_SOURCE_CHECK;
import static uk.gov.di.ipv.core.library.domain.Cri.DCMAW;
import static uk.gov.di.ipv.core.library.domain.Cri.DCMAW_ASYNC;
import static uk.gov.di.ipv.core.library.domain.Cri.DRIVING_LICENCE;
import static uk.gov.di.ipv.core.library.domain.ErrorResponse.FAILED_TO_VALIDATE_VERIFIABLE_CREDENTIAL_RESPONSE;
import static uk.gov.di.ipv.core.library.domain.ErrorResponse.MISSING_TARGET_VOT;
import static uk.gov.di.ipv.core.library.helpers.LogHelper.LogField.LOG_CRI_ID;
import static uk.gov.di.ipv.core.library.journeys.JourneyUris.JOURNEY_ACCESS_DENIED_PATH;
import static uk.gov.di.ipv.core.library.journeys.JourneyUris.JOURNEY_DL_AUTH_SOURCE_CHECK_PATH;
import static uk.gov.di.ipv.core.library.journeys.JourneyUris.JOURNEY_ENHANCED_VERIFICATION_PATH;
import static uk.gov.di.ipv.core.library.journeys.JourneyUris.JOURNEY_ERROR_PATH;
import static uk.gov.di.ipv.core.library.journeys.JourneyUris.JOURNEY_FAIL_WITH_NO_CI_PATH;
import static uk.gov.di.ipv.core.library.journeys.JourneyUris.JOURNEY_NEXT_PATH;
import static uk.gov.di.ipv.core.library.journeys.JourneyUris.JOURNEY_TEMPORARILY_UNAVAILABLE_PATH;

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
    private static final JourneyResponse JOURNEY_DL_AUTH_SOURCE_CHECK =
            new JourneyResponse(JOURNEY_DL_AUTH_SOURCE_CHECK_PATH);
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
    private final CimitService cimitService;
    private final CimitUtilityService cimitUtilityService;
    private final ConfigService configService;
    private final IpvSessionService ipvSessionService;

    @ExcludeFromGeneratedCoverageReport
    public CriCheckingService(
            ConfigService configService,
            AuditService auditService,
            UserIdentityService userIdentityService,
            CimitService cimitService,
            CimitUtilityService cimitUtilityService,
            IpvSessionService ipvSessionService) {
        this.configService = configService;
        this.auditService = auditService;
        this.userIdentityService = userIdentityService;
        this.cimitService = cimitService;
        this.cimitUtilityService = cimitUtilityService;
        this.ipvSessionService = ipvSessionService;
    }

    public JourneyResponse handleCallbackError(
            CriCallbackRequest callbackRequest, ClientOAuthSessionItem clientOAuthSessionItem) {
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
                        configService.getParameter(ConfigurationVariable.COMPONENT_ID),
                        auditEventUser,
                        extensions,
                        new AuditRestrictedDeviceInformation(deviceInformation)));

        if (!ALLOWED_OAUTH_ERROR_CODES.contains(errorCode)) {
            LOGGER.warn(LogHelper.buildLogMessage("Unknown Oauth error code received"));
        }

        LOGGER.info(
                LogHelper.buildErrorMessage(
                        "OAuth error received from CRI", errorDescription, errorCode));

        return (switch (errorCode) {
            case OAuth2Error.ACCESS_DENIED_CODE -> JOURNEY_ACCESS_DENIED;
            case OAuth2Error.TEMPORARILY_UNAVAILABLE_CODE -> JOURNEY_TEMPORARILY_UNAVAILABLE;
            case OAuth2Error.INVALID_REQUEST_CODE -> JOURNEY_INVALID_REQUEST;
            default -> {
                LOGGER.error(
                        LogHelper.buildErrorMessage("Unacceptable callback error code", errorCode));
                yield JOURNEY_ERROR;
            }
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
            throw new InvalidCriCallbackRequestException(ErrorResponse.MISSING_IPV_SESSION_ID);
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
            String ipAddress,
            ClientOAuthSessionItem clientOAuthSessionItem,
            IpvSessionItem ipvSessionItem,
            List<VerifiableCredential> sessionVcs)
            throws CiRetrievalException, ConfigException, HttpResponseExceptionWithErrorBody,
                    CiExtractionException {
        var scopeClaims = clientOAuthSessionItem.getScopeClaims();
        var isReverification = scopeClaims.contains(ScopeConstants.REVERIFICATION);
        if (!isReverification) {
            var contraIndicatorsVc =
                    cimitService.getContraIndicatorsVc(
                            clientOAuthSessionItem.getUserId(),
                            clientOAuthSessionItem.getGovukSigninJourneyId(),
                            ipAddress,
                            ipvSessionItem);
            var cis = cimitUtilityService.getContraIndicatorsFromVc(contraIndicatorsVc);

            // Check CIs only against the target Vot so we don't send the user on an unnecessary
            // mitigation journey.
            var journeyResponse =
                    cimitUtilityService.getMitigationJourneyIfBreaching(
                            cis,
                            Optional.ofNullable(ipvSessionItem.getTargetVot())
                                    .orElseThrow(
                                            () ->
                                                    new HttpResponseExceptionWithErrorBody(
                                                            HttpStatusCode.INTERNAL_SERVER_ERROR,
                                                            MISSING_TARGET_VOT)));
            if (journeyResponse.isPresent()) {
                var jr = journeyResponse.get();
                if (jr.toString().equals(JOURNEY_ENHANCED_VERIFICATION_PATH)
                        && configService.enabled(DL_AUTH_SOURCE_CHECK)
                        && requiresAuthoritativeSourceCheck(newVcs, sessionVcs)) {
                    return JOURNEY_DL_AUTH_SOURCE_CHECK;
                }
                return jr;
            }
        }

        if (!userIdentityService.areVcsCorrelated(sessionVcs)) {
            if (isReverification) {
                setFailedIdentityCheckOnIpvSessionItem(ipvSessionItem);
            }
            return JOURNEY_VCS_NOT_CORRELATED;
        }

        for (var vc : newVcs) {
            if (!VcHelper.isSuccessfulVc(vc)) {
                if (isReverification) {
                    setFailedIdentityCheckOnIpvSessionItem(ipvSessionItem);
                }
                return JOURNEY_FAIL_WITH_NO_CI;
            }
        }

        if (configService.enabled(DL_AUTH_SOURCE_CHECK)
                && requiresAuthoritativeSourceCheck(newVcs, sessionVcs)) {
            return JOURNEY_DL_AUTH_SOURCE_CHECK;
        }

        return JOURNEY_NEXT;
    }

    private void setFailedIdentityCheckOnIpvSessionItem(IpvSessionItem ipvSessionItem) {
        ipvSessionItem.setFailureCode(ReverificationFailureCode.IDENTITY_CHECK_FAILED);
        ipvSessionService.updateIpvSession(ipvSessionItem);
    }

    private boolean requiresAuthoritativeSourceCheck(
            List<VerifiableCredential> newVcs, List<VerifiableCredential> sessionVcs) {

        var dcmawVc = findSuccessfulVcFromCri(DCMAW, newVcs);
        var dcmawAsyncVc = findSuccessfulVcFromCri(DCMAW_ASYNC, newVcs);

        if (dcmawVc.isPresent() && dcmawAsyncVc.isPresent()) {
            throw new InvalidParameterException("New VCs contains both DCMAW and DCMAW Async VCs");
        }

        var newVc = dcmawVc.isPresent() ? dcmawVc : dcmawAsyncVc;

        return newVc.map(this::getDrivingPermitIdentifier)
                .map(
                        dcmawDpId ->
                                findSuccessfulVcFromCri(DRIVING_LICENCE, sessionVcs)
                                        .map(
                                                dlVc ->
                                                        !Objects.equals(
                                                                dcmawDpId,
                                                                getDrivingPermitIdentifier(dlVc)))
                                        .orElse(true))
                .orElse(false);
    }

    private Optional<VerifiableCredential> findSuccessfulVcFromCri(
            Cri cri, List<VerifiableCredential> vcs) {
        return vcs.stream()
                .filter(vc -> cri.equals(vc.getCri()))
                .filter(VcHelper::isSuccessfulVc)
                .findFirst();
    }

    private String getDrivingPermitIdentifier(VerifiableCredential vc) {
        if (vc.getCredential().getCredentialSubject()
                        instanceof IdentityCheckSubject identityCheckSubject
                && identityCheckSubject.getDrivingPermit() != null
                && !identityCheckSubject.getDrivingPermit().isEmpty()) {
            var permit = identityCheckSubject.getDrivingPermit().get(0);
            return String.format(
                            "drivingPermit/%s/%s/%s/%s",
                            permit.getIssuingCountry(),
                            permit.getIssuedBy(),
                            permit.getPersonalNumber(),
                            permit.getIssueDate())
                    .toUpperCase();
        }
        LOGGER.warn(
                LogHelper.buildLogMessage("Unable to get driving permit identifier from VC")
                        .with(LOG_CRI_ID.getFieldName(), vc.getCri()));
        return null;
    }
}
