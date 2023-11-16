package uk.gov.di.ipv.core.processcricallback;

import com.amazonaws.services.lambda.runtime.Context;
import com.amazonaws.services.lambda.runtime.RequestHandler;
import com.fasterxml.jackson.core.JsonProcessingException;
import com.nimbusds.oauth2.sdk.OAuth2Error;
import com.nimbusds.oauth2.sdk.http.HTTPResponse;
import org.apache.http.HttpStatus;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import software.amazon.lambda.powertools.logging.Logging;
import software.amazon.lambda.powertools.tracing.Tracing;
import uk.gov.di.ipv.core.library.annotations.ExcludeFromGeneratedCoverageReport;
import uk.gov.di.ipv.core.library.cimit.exception.CiPostMitigationsException;
import uk.gov.di.ipv.core.library.cimit.exception.CiPutException;
import uk.gov.di.ipv.core.library.cimit.exception.CiRetrievalException;
import uk.gov.di.ipv.core.library.domain.ErrorResponse;
import uk.gov.di.ipv.core.library.domain.JourneyErrorResponse;
import uk.gov.di.ipv.core.library.domain.JourneyResponse;
import uk.gov.di.ipv.core.library.dto.VisitedCredentialIssuerDetailsDto;
import uk.gov.di.ipv.core.library.exceptions.*;
import uk.gov.di.ipv.core.library.helpers.LogHelper;
import uk.gov.di.ipv.core.library.helpers.StepFunctionHelpers;
import uk.gov.di.ipv.core.library.kmses256signer.KmsEs256Signer;
import uk.gov.di.ipv.core.library.persistence.item.CriOAuthSessionItem;
import uk.gov.di.ipv.core.library.persistence.item.IpvSessionItem;
import uk.gov.di.ipv.core.library.service.AuditService;
import uk.gov.di.ipv.core.library.service.CiMitService;
import uk.gov.di.ipv.core.library.service.ClientOAuthSessionDetailsService;
import uk.gov.di.ipv.core.library.service.ConfigService;
import uk.gov.di.ipv.core.library.service.CriOAuthSessionService;
import uk.gov.di.ipv.core.library.service.CriResponseService;
import uk.gov.di.ipv.core.library.service.IpvSessionService;
import uk.gov.di.ipv.core.library.service.UserIdentityService;
import uk.gov.di.ipv.core.library.verifiablecredential.exception.VerifiableCredentialResponseException;
import uk.gov.di.ipv.core.library.verifiablecredential.helpers.VcHelper;
import uk.gov.di.ipv.core.library.verifiablecredential.service.VerifiableCredentialService;
import uk.gov.di.ipv.core.library.verifiablecredential.validator.VerifiableCredentialJwtValidator;
import uk.gov.di.ipv.core.processcricallback.dto.CriCallbackRequest;
import uk.gov.di.ipv.core.processcricallback.service.CriApiService;
import uk.gov.di.ipv.core.processcricallback.service.CriCheckingService;
import uk.gov.di.ipv.core.processcricallback.service.CriStoringService;

import java.text.ParseException;
import java.util.Map;

import static uk.gov.di.ipv.core.library.domain.CriConstants.DCMAW_CRI;
import static uk.gov.di.ipv.core.library.journeyuris.JourneyUris.JOURNEY_ERROR_PATH;
import static uk.gov.di.ipv.core.library.journeyuris.JourneyUris.JOURNEY_NOT_FOUND_PATH;

public class ProcessCriCallbackHandler
        implements RequestHandler<CriCallbackRequest, Map<String, Object>> {
    private static final Logger LOGGER = LogManager.getLogger();
    private static final JourneyResponse JOURNEY_ERROR = new JourneyResponse(JOURNEY_ERROR_PATH);
    private static final JourneyResponse JOURNEY_NOT_FOUND =
            new JourneyResponse(JOURNEY_NOT_FOUND_PATH);
    private static final String PYI_ATTEMPT_RECOVERY_PAGE_ID = "pyi-attempt-recovery";
    private static final String PYI_TIMEOUT_RECOVERABLE_PAGE_ID = "pyi-timeout-recoverable";
    private final ConfigService configService;
    private final CriApiService criApiService;
    private final CriStoringService criStoringService;
    private final CriCheckingService criCheckingService;
    private final IpvSessionService ipvSessionService;
    private final CriOAuthSessionService criOAuthSessionService;
    private final ClientOAuthSessionDetailsService clientOAuthSessionDetailsService;

    private IpvSessionItem ipvSessionItem = null;
    private CriOAuthSessionItem criOAuthSessionItem = null;

    public ProcessCriCallbackHandler(
            ConfigService configService,
            IpvSessionService ipvSessionService,
            CriOAuthSessionService criOAuthSessionService,
            ClientOAuthSessionDetailsService clientOAuthSessionDetailsService,
            CriApiService vcFetchingService,
            CriStoringService criStoringService,
            CriCheckingService criCheckingService) {
        this.configService = configService;
        this.criApiService = vcFetchingService;
        this.criStoringService = criStoringService;
        this.criCheckingService = criCheckingService;
        this.ipvSessionService = ipvSessionService;
        this.criOAuthSessionService = criOAuthSessionService;
        this.clientOAuthSessionDetailsService = clientOAuthSessionDetailsService;
        VcHelper.setConfigService(this.configService);
    }

    @ExcludeFromGeneratedCoverageReport
    public ProcessCriCallbackHandler() {
        configService = new ConfigService();
        ipvSessionService = new IpvSessionService(configService);
        criOAuthSessionService = new CriOAuthSessionService(configService);
        clientOAuthSessionDetailsService = new ClientOAuthSessionDetailsService(configService);

        var userIdentityService = new UserIdentityService(configService);
        var auditService = new AuditService(AuditService.getDefaultSqsClient(), configService);
        var verifiableCredentialService = new VerifiableCredentialService(configService);
        var verifiableCredentialJwtValidator = new VerifiableCredentialJwtValidator(configService);
        var ciMitService = new CiMitService(configService);
        var criResponseService = new CriResponseService(configService);
        var signer = new KmsEs256Signer();

        signer.setKeyId(configService.getSigningKeyId());
        VcHelper.setConfigService(configService);

        criApiService = new CriApiService(configService, signer, criOAuthSessionService);
        criCheckingService =
                new CriCheckingService(
                        configService,
                        auditService,
                        userIdentityService,
                        ciMitService,
                        criOAuthSessionService,
                        verifiableCredentialJwtValidator);
        criStoringService =
                new CriStoringService(
                        configService,
                        auditService,
                        criResponseService,
                        verifiableCredentialService,
                        ciMitService);
    }

    @Override
    @Tracing
    @Logging(clearState = true)
    public Map<String, Object> handleRequest(CriCallbackRequest callbackRequest, Context context) {
        try {
            // Validate Callback Attributes
            validateCallbackRequest(callbackRequest);

            // Get/ set session items/ config
            criOAuthSessionItem = getValidCriOauthSessionItem(callbackRequest);
            ipvSessionItem = ipvSessionService.getIpvSession(callbackRequest.getIpvSessionId());
            var clientOAuthSessionItem =
                    clientOAuthSessionDetailsService.getClientOAuthSession(
                            ipvSessionItem.getClientOAuthSessionId());
            configService.setFeatureSet(callbackRequest.getFeatureSet());
            var criConfig = configService.getCriConfig(criOAuthSessionItem);

            // Attach variables to logs
            LogHelper.attachGovukSigninJourneyIdToLogs(
                    clientOAuthSessionItem.getGovukSigninJourneyId());
            LogHelper.attachIpvSessionIdToLogs(callbackRequest.getIpvSessionId());
            LogHelper.attachFeatureSetToLogs(callbackRequest.getFeatureSet());
            LogHelper.attachCriIdToLogs(callbackRequest.getCredentialIssuerId());
            LogHelper.attachComponentIdToLogs(configService);

            // Check for callback error
            if (callbackRequest.getError() != null) {
                return criCheckingService.handleCallbackError(
                        callbackRequest, clientOAuthSessionItem, ipvSessionItem);
            }

            // Retrieve, store and check cri credentials
            var apiKey = criApiService.getApiKey(callbackRequest);
            var accessToken = criApiService.fetchAccessToken(apiKey, callbackRequest);
            var vcResponse =
                    criApiService.fetchVerifiableCredential(accessToken, apiKey, callbackRequest);

            criCheckingService.validateVcResponse(
                    vcResponse, callbackRequest, clientOAuthSessionItem);

            switch (vcResponse.getCredentialStatus()) {
                case CREATED -> criStoringService.storeCreatedVcs(
                        vcResponse, callbackRequest, clientOAuthSessionItem);

                case PENDING -> criStoringService.storeCriResponse(
                        callbackRequest, clientOAuthSessionItem);
            }

            var journeyResponse =
                    criCheckingService.checkVcResponse(
                            vcResponse, callbackRequest, clientOAuthSessionItem, ipvSessionItem);

            return journeyResponse.toObjectMap();
        } catch (HttpResponseExceptionWithErrorBody e) {
            ErrorResponse errorResponse = e.getErrorResponse();
            LogHelper.logErrorMessage(
                    "Error in process cri callback lambda",
                    errorResponse.getCode(),
                    errorResponse.getMessage());

            return switch (errorResponse) {
                case INVALID_OAUTH_STATE -> StepFunctionHelpers.generatePageOutputMap(
                        "error", HttpStatus.SC_BAD_REQUEST, PYI_ATTEMPT_RECOVERY_PAGE_ID);
                case NO_IPV_FOR_CRI_OAUTH_SESSION -> {
                    var pageOutput =
                            StepFunctionHelpers.generatePageOutputMap(
                                    "error",
                                    HttpStatus.SC_UNAUTHORIZED,
                                    PYI_TIMEOUT_RECOVERABLE_PAGE_ID);
                    pageOutput.put(
                            "clientOAuthSessionId", criOAuthSessionItem.getClientOAuthSessionId());
                    yield pageOutput;
                }
                default -> StepFunctionHelpers.generateErrorOutputMap(
                        HttpStatus.SC_BAD_REQUEST, errorResponse);
            };
        } catch (JsonProcessingException | SqsException e) {
            LOGGER.error("Failed to send audit event to SQS queue because: {}", e.getMessage());

            var visitedCri =
                    new VisitedCredentialIssuerDetailsDto(
                            callbackRequest.getCredentialIssuerId(),
                            null,
                            false,
                            OAuth2Error.SERVER_ERROR_CODE);

            ipvSessionItem.addVisitedCredentialIssuerDetails(visitedCri);

            return JOURNEY_ERROR.toObjectMap();
        } catch (ParseException e) {
            LOGGER.error("Unable to get JWT claims set", e);
            return new JourneyErrorResponse(
                            JOURNEY_ERROR_PATH,
                            HttpStatus.SC_INTERNAL_SERVER_ERROR,
                            ErrorResponse.FAILED_TO_PARSE_ISSUED_CREDENTIALS)
                    .toObjectMap();
        } catch (VerifiableCredentialException
                | VerifiableCredentialResponseException
                | CiPutException
                | CiPostMitigationsException e) {
            var visitedCri =
                    new VisitedCredentialIssuerDetailsDto(
                            callbackRequest.getCredentialIssuerId(),
                            null,
                            false,
                            OAuth2Error.SERVER_ERROR_CODE);

            ipvSessionItem.addVisitedCredentialIssuerDetails(visitedCri);

            if (callbackRequest.getCredentialIssuerId().equals(DCMAW_CRI)
                    && e instanceof VerifiableCredentialException vce
                    && vce.getHttpStatusCode() == HTTPResponse.SC_NOT_FOUND) {
                LogHelper.logErrorMessage(
                        "404 received from DCMAW CRI", vce.getErrorResponse().getMessage());
                return JOURNEY_NOT_FOUND.toObjectMap();
            }

            return JOURNEY_ERROR.toObjectMap();
        } catch (CiRetrievalException e) {
            LOGGER.error("Error when fetching CIs from storage system", e);
            return new JourneyErrorResponse(
                            JOURNEY_ERROR_PATH,
                            HttpStatus.SC_INTERNAL_SERVER_ERROR,
                            ErrorResponse.FAILED_TO_GET_STORED_CIS)
                    .toObjectMap();
        } catch (ConfigException e) {
            LOGGER.error("Configuration error", e);
            return new JourneyErrorResponse(
                            JOURNEY_ERROR_PATH,
                            HttpStatus.SC_INTERNAL_SERVER_ERROR,
                            ErrorResponse.FAILED_TO_PARSE_CONFIG)
                    .toObjectMap();
        } catch (CredentialParseException e) {
            LOGGER.error("Failed to parse successful VC Store items.", e);
            return new JourneyErrorResponse(
                            JOURNEY_ERROR_PATH,
                            HttpStatus.SC_INTERNAL_SERVER_ERROR,
                            ErrorResponse.FAILED_TO_PARSE_SUCCESSFUL_VC_STORE_ITEMS)
                    .toObjectMap();
        } finally {
            ipvSessionService.updateIpvSession(ipvSessionItem);
        }
    }

    private void validateCallbackRequest(CriCallbackRequest callbackRequest)
            throws HttpResponseExceptionWithErrorBody {
        var criId = callbackRequest.getCredentialIssuerId();
        if (criId.isBlank()) {
            throw new HttpResponseExceptionWithErrorBody(
                    HttpStatus.SC_BAD_REQUEST, ErrorResponse.MISSING_CREDENTIAL_ISSUER_ID);
        }
        if (configService.getCredentialIssuerActiveConnectionConfig(criId) == null) {
            throw new HttpResponseExceptionWithErrorBody(
                    HttpStatus.SC_BAD_REQUEST, ErrorResponse.INVALID_CREDENTIAL_ISSUER_ID);
        }

        var authorisationCode = callbackRequest.getAuthorizationCode();
        if (authorisationCode.isBlank()) {
            throw new HttpResponseExceptionWithErrorBody(
                    HttpStatus.SC_BAD_REQUEST, ErrorResponse.MISSING_AUTHORIZATION_CODE);
        }

        var ipvSessionId = callbackRequest.getIpvSessionId();
        if (ipvSessionId.isBlank()) {
            throw new HttpResponseExceptionWithErrorBody(
                    HttpStatus.SC_BAD_REQUEST, ErrorResponse.MISSING_IPV_SESSION_ID);
        }

        var criOAuthSessionId = callbackRequest.getState();
        if (criOAuthSessionId.isBlank()) {
            throw new HttpResponseExceptionWithErrorBody(
                    HttpStatus.SC_BAD_REQUEST, ErrorResponse.MISSING_OAUTH_STATE);
        }
    }

    private CriOAuthSessionItem getValidCriOauthSessionItem(CriCallbackRequest callbackRequest)
            throws HttpResponseExceptionWithErrorBody {
        CriOAuthSessionItem criOAuthSessionItem =
                criOAuthSessionService.getCriOauthSessionItem(callbackRequest.getState());
        if (criOAuthSessionItem == null) {
            throw new HttpResponseExceptionWithErrorBody(
                    HttpStatus.SC_BAD_REQUEST, ErrorResponse.INVALID_OAUTH_STATE);
        }

        if (!criOAuthSessionItem.getCriId().equals(callbackRequest.getCredentialIssuerId())) {
            throw new HttpResponseExceptionWithErrorBody(
                    HttpStatus.SC_BAD_REQUEST, ErrorResponse.INVALID_OAUTH_STATE);
        }
        return criOAuthSessionItem;
    }
}
