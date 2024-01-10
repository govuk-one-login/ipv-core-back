package uk.gov.di.ipv.core.processcricallback;

import com.amazonaws.services.lambda.runtime.Context;
import com.amazonaws.services.lambda.runtime.RequestHandler;
import com.amazonaws.services.lambda.runtime.events.APIGatewayProxyRequestEvent;
import com.amazonaws.services.lambda.runtime.events.APIGatewayProxyResponseEvent;
import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.nimbusds.jwt.SignedJWT;
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
import uk.gov.di.ipv.core.library.cristoringservice.CriStoringService;
import uk.gov.di.ipv.core.library.domain.ErrorResponse;
import uk.gov.di.ipv.core.library.domain.JourneyErrorResponse;
import uk.gov.di.ipv.core.library.domain.JourneyResponse;
import uk.gov.di.ipv.core.library.dto.CriCallbackRequest;
import uk.gov.di.ipv.core.library.exceptions.ConfigException;
import uk.gov.di.ipv.core.library.exceptions.CredentialParseException;
import uk.gov.di.ipv.core.library.exceptions.HttpResponseExceptionWithErrorBody;
import uk.gov.di.ipv.core.library.exceptions.SqsException;
import uk.gov.di.ipv.core.library.exceptions.VerifiableCredentialException;
import uk.gov.di.ipv.core.library.helpers.ApiGatewayResponseGenerator;
import uk.gov.di.ipv.core.library.helpers.LogHelper;
import uk.gov.di.ipv.core.library.helpers.SecureTokenHelper;
import uk.gov.di.ipv.core.library.helpers.StepFunctionHelpers;
import uk.gov.di.ipv.core.library.kmses256signer.KmsEs256Signer;
import uk.gov.di.ipv.core.library.service.AuditService;
import uk.gov.di.ipv.core.library.service.CiMitService;
import uk.gov.di.ipv.core.library.service.CiMitUtilityService;
import uk.gov.di.ipv.core.library.service.ClientOAuthSessionDetailsService;
import uk.gov.di.ipv.core.library.service.ConfigService;
import uk.gov.di.ipv.core.library.service.CriOAuthSessionService;
import uk.gov.di.ipv.core.library.service.CriResponseService;
import uk.gov.di.ipv.core.library.service.IpvSessionService;
import uk.gov.di.ipv.core.library.service.UserIdentityService;
import uk.gov.di.ipv.core.library.verifiablecredential.domain.VerifiableCredentialStatus;
import uk.gov.di.ipv.core.library.verifiablecredential.helpers.VcHelper;
import uk.gov.di.ipv.core.library.verifiablecredential.service.VerifiableCredentialService;
import uk.gov.di.ipv.core.library.verifiablecredential.validator.VerifiableCredentialJwtValidator;
import uk.gov.di.ipv.core.processcricallback.exception.CriApiException;
import uk.gov.di.ipv.core.processcricallback.exception.InvalidCriCallbackRequestException;
import uk.gov.di.ipv.core.processcricallback.exception.ParseCriCallbackRequestException;
import uk.gov.di.ipv.core.processcricallback.service.CriApiService;
import uk.gov.di.ipv.core.processcricallback.service.CriCheckingService;

import java.text.ParseException;
import java.time.Clock;

import static uk.gov.di.ipv.core.library.domain.CriConstants.DCMAW_CRI;
import static uk.gov.di.ipv.core.library.journeyuris.JourneyUris.JOURNEY_ERROR_PATH;
import static uk.gov.di.ipv.core.library.journeyuris.JourneyUris.JOURNEY_NOT_FOUND_PATH;

public class ProcessCriCallbackHandler
        implements RequestHandler<APIGatewayProxyRequestEvent, APIGatewayProxyResponseEvent> {
    private static final Logger LOGGER = LogManager.getLogger();
    private static final ObjectMapper objectMapper = new ObjectMapper();
    private static final String PYI_ATTEMPT_RECOVERY_PAGE_ID = "pyi-attempt-recovery";
    private static final String PYI_TIMEOUT_RECOVERABLE_PAGE_ID = "pyi-timeout-recoverable";
    private static final JourneyResponse JOURNEY_NOT_FOUND =
            new JourneyResponse(JOURNEY_NOT_FOUND_PATH);
    private final ConfigService configService;
    private final CriApiService criApiService;
    private final CriStoringService criStoringService;
    private final CriCheckingService criCheckingService;
    private final IpvSessionService ipvSessionService;
    private final CriOAuthSessionService criOAuthSessionService;
    private final VerifiableCredentialJwtValidator verifiableCredentialJwtValidator;
    private final ClientOAuthSessionDetailsService clientOAuthSessionDetailsService;

    @SuppressWarnings("java:S107") // Methods should not have too many parameters
    public ProcessCriCallbackHandler(
            ConfigService configService,
            IpvSessionService ipvSessionService,
            CriOAuthSessionService criOAuthSessionService,
            VerifiableCredentialJwtValidator verifiableCredentialJwtValidator,
            ClientOAuthSessionDetailsService clientOAuthSessionDetailsService,
            CriApiService criApiService,
            CriStoringService criStoringService,
            CriCheckingService criCheckingService) {
        this.configService = configService;
        this.criApiService = criApiService;
        this.criStoringService = criStoringService;
        this.criCheckingService = criCheckingService;
        this.ipvSessionService = ipvSessionService;
        this.criOAuthSessionService = criOAuthSessionService;
        this.verifiableCredentialJwtValidator = verifiableCredentialJwtValidator;
        this.clientOAuthSessionDetailsService = clientOAuthSessionDetailsService;
        VcHelper.setConfigService(this.configService);
    }

    @ExcludeFromGeneratedCoverageReport
    public ProcessCriCallbackHandler() {
        configService = new ConfigService();
        ipvSessionService = new IpvSessionService(configService);
        criOAuthSessionService = new CriOAuthSessionService(configService);
        verifiableCredentialJwtValidator = new VerifiableCredentialJwtValidator(configService);
        clientOAuthSessionDetailsService = new ClientOAuthSessionDetailsService(configService);

        var userIdentityService = new UserIdentityService(configService);
        var auditService = new AuditService(AuditService.getDefaultSqsClient(), configService);
        var verifiableCredentialService = new VerifiableCredentialService(configService);
        var ciMitService = new CiMitService(configService);
        var ciMitUtilityService = new CiMitUtilityService(configService);
        var criResponseService = new CriResponseService(configService);
        var signer = new KmsEs256Signer();

        signer.setKeyId(configService.getSigningKeyId());
        VcHelper.setConfigService(configService);

        criApiService =
                new CriApiService(
                        configService,
                        signer,
                        SecureTokenHelper.getInstance(),
                        Clock.systemDefaultZone());
        criCheckingService =
                new CriCheckingService(
                        configService,
                        auditService,
                        userIdentityService,
                        ciMitService,
                        ciMitUtilityService,
                        verifiableCredentialService);
        criStoringService =
                new CriStoringService(
                        configService,
                        auditService,
                        criResponseService,
                        verifiableCredentialService,
                        ciMitService);
    }

    @SuppressWarnings("java:S3776") // Cognitive Complexity of methods should not be too high
    @Override
    @Tracing
    @Logging(clearState = true)
    public APIGatewayProxyResponseEvent handleRequest(
            APIGatewayProxyRequestEvent input, Context context) {
        CriCallbackRequest callbackRequest = null;

        try {
            callbackRequest = parseCallbackRequest(input);

            var journeyResponse = getJourneyResponse(callbackRequest);

            return ApiGatewayResponseGenerator.proxyJsonResponse(HttpStatus.SC_OK, journeyResponse);
        } catch (ParseCriCallbackRequestException e) {
            return buildErrorResponse(
                    e,
                    HttpStatus.SC_BAD_REQUEST,
                    ErrorResponse.FAILED_TO_PARSE_CRI_CALLBACK_REQUEST);
        } catch (InvalidCriCallbackRequestException e) {
            if (e.getErrorResponse() == ErrorResponse.NO_IPV_FOR_CRI_OAUTH_SESSION) {
                LOGGER.error(e.getErrorResponse(), e);
                var pageOutput =
                        StepFunctionHelpers.generatePageOutputMap(
                                "error",
                                HttpStatus.SC_UNAUTHORIZED,
                                PYI_TIMEOUT_RECOVERABLE_PAGE_ID);
                var criOAuthSessionItem =
                        criOAuthSessionService.getCriOauthSessionItem(callbackRequest.getState());
                if (criOAuthSessionItem != null) {
                    pageOutput.put(
                            "clientOAuthSessionId", criOAuthSessionItem.getClientOAuthSessionId());
                }
                return ApiGatewayResponseGenerator.proxyJsonResponse(
                        HttpStatus.SC_UNAUTHORIZED, pageOutput);
            }
            if (e.getErrorResponse() == ErrorResponse.INVALID_OAUTH_STATE) {
                LOGGER.error(e.getErrorResponse(), e);
                return ApiGatewayResponseGenerator.proxyJsonResponse(
                        HttpStatus.SC_BAD_REQUEST,
                        StepFunctionHelpers.generatePageOutputMap(
                                "error", HttpStatus.SC_BAD_REQUEST, PYI_ATTEMPT_RECOVERY_PAGE_ID));
            }
            return buildErrorResponse(e, HttpStatus.SC_BAD_REQUEST, e.getErrorResponse());
        } catch (HttpResponseExceptionWithErrorBody e) {
            return buildErrorResponse(e, HttpStatus.SC_BAD_REQUEST, e.getErrorResponse());
        } catch (JsonProcessingException | SqsException e) {
            return buildErrorResponse(
                    e,
                    HttpStatus.SC_INTERNAL_SERVER_ERROR,
                    ErrorResponse.FAILED_TO_SEND_AUDIT_EVENT);
        } catch (ParseException e) {
            return buildErrorResponse(
                    e,
                    HttpStatus.SC_INTERNAL_SERVER_ERROR,
                    ErrorResponse.FAILED_TO_PARSE_ISSUED_CREDENTIALS);
        } catch (VerifiableCredentialException e) {
            return buildErrorResponse(e, e.getHttpStatusCode(), e.getErrorResponse());
        } catch (CiPutException | CiPostMitigationsException e) {
            return buildErrorResponse(
                    e,
                    HttpStatus.SC_INTERNAL_SERVER_ERROR,
                    ErrorResponse.FAILED_TO_SAVE_CREDENTIAL);
        } catch (CiRetrievalException e) {
            return buildErrorResponse(
                    e, HttpStatus.SC_INTERNAL_SERVER_ERROR, ErrorResponse.FAILED_TO_GET_STORED_CIS);
        } catch (ConfigException e) {
            return buildErrorResponse(
                    e, HttpStatus.SC_INTERNAL_SERVER_ERROR, ErrorResponse.FAILED_TO_PARSE_CONFIG);
        } catch (CredentialParseException e) {
            return buildErrorResponse(
                    e,
                    HttpStatus.SC_INTERNAL_SERVER_ERROR,
                    ErrorResponse.FAILED_TO_PARSE_SUCCESSFUL_VC_STORE_ITEMS);
        } catch (CriApiException e) {
            if (DCMAW_CRI.equals(callbackRequest.getCredentialIssuerId())
                    && e.getHttpStatusCode() == HTTPResponse.SC_NOT_FOUND) {
                LogHelper.logErrorMessage(
                        "404 received from DCMAW CRI", e.getErrorResponse().getMessage());
                return ApiGatewayResponseGenerator.proxyJsonResponse(
                        HttpStatus.SC_OK, JOURNEY_NOT_FOUND);
            }
            return buildErrorResponse(e, e.getHttpStatusCode(), e.getErrorResponse());
        }
    }

    private CriCallbackRequest parseCallbackRequest(APIGatewayProxyRequestEvent input)
            throws ParseCriCallbackRequestException {
        try {
            var callbackRequest = objectMapper.readValue(input.getBody(), CriCallbackRequest.class);
            callbackRequest.setIpvSessionId(input.getHeaders().get("ipv-session-id"));
            callbackRequest.setFeatureSet(input.getHeaders().get("feature-set"));
            callbackRequest.setIpAddress(input.getHeaders().get("ip-address"));

            return callbackRequest;
        } catch (JsonProcessingException e) {
            throw new ParseCriCallbackRequestException(e);
        }
    }

    public JourneyResponse getJourneyResponse(CriCallbackRequest callbackRequest)
            throws SqsException, ParseException, JsonProcessingException,
                    HttpResponseExceptionWithErrorBody, ConfigException, CiRetrievalException,
                    CriApiException, VerifiableCredentialException, CiPostMitigationsException,
                    CiPutException, CredentialParseException, InvalidCriCallbackRequestException {
        // Validate callback sessions
        criCheckingService.validateSessionIds(callbackRequest);

        // Get/ set session items/ config
        var ipvSessionItem = ipvSessionService.getIpvSession(callbackRequest.getIpvSessionId());

        var clientOAuthSessionItem =
                clientOAuthSessionDetailsService.getClientOAuthSession(
                        ipvSessionItem.getClientOAuthSessionId());
        var criOAuthSessionItem =
                ipvSessionItem.getCriOAuthSessionId() != null
                        ? criOAuthSessionService.getCriOauthSessionItem(
                                ipvSessionItem.getCriOAuthSessionId())
                        : null;
        configService.setFeatureSet(callbackRequest.getFeatureSet());

        // Attach variables to logs
        LogHelper.attachGovukSigninJourneyIdToLogs(
                clientOAuthSessionItem.getGovukSigninJourneyId());
        LogHelper.attachIpvSessionIdToLogs(callbackRequest.getIpvSessionId());
        LogHelper.attachFeatureSetToLogs(callbackRequest.getFeatureSet());
        LogHelper.attachCriIdToLogs(callbackRequest.getCredentialIssuerId());
        LogHelper.attachComponentIdToLogs(configService);

        // Validate callback request
        if (callbackRequest.getError() != null) {
            criCheckingService.validateOAuthForError(
                    callbackRequest, criOAuthSessionItem, ipvSessionItem);
            return criCheckingService.handleCallbackError(callbackRequest, clientOAuthSessionItem);
        }
        criCheckingService.validateCallbackRequest(callbackRequest, criOAuthSessionItem);

        // Retrieve, store and check cri credentials
        var accessToken = criApiService.fetchAccessToken(callbackRequest, criOAuthSessionItem);
        var vcResponse =
                criApiService.fetchVerifiableCredential(
                        accessToken, callbackRequest, criOAuthSessionItem);

        if (VerifiableCredentialStatus.PENDING.equals(vcResponse.getCredentialStatus())) {
            criCheckingService.validatePendingVcResponse(vcResponse, clientOAuthSessionItem);
            criStoringService.storeCriResponse(callbackRequest, clientOAuthSessionItem);
        } else {
            for (SignedJWT vc : vcResponse.getVerifiableCredentials()) {
                if (criOAuthSessionItem == null) {
                    // We should never get here due to earlier null checks.
                    // This is to satisfy compile time warning
                    throw new InvalidCriCallbackRequestException(ErrorResponse.INVALID_OAUTH_STATE);
                } else {
                    verifiableCredentialJwtValidator.validate(
                            vc,
                            configService.getCriConfig(criOAuthSessionItem),
                            clientOAuthSessionItem.getUserId());
                }
            }
            criStoringService.storeVcs(
                    callbackRequest.getCredentialIssuerId(),
                    callbackRequest.getIpAddress(),
                    vcResponse.getVerifiableCredentials(),
                    clientOAuthSessionItem,
                    ipvSessionItem);
            ipvSessionService.updateIpvSession(ipvSessionItem);
        }

        return criCheckingService.checkVcResponse(
                vcResponse, callbackRequest, clientOAuthSessionItem);
    }

    private APIGatewayProxyResponseEvent buildErrorResponse(
            Exception e, int status, ErrorResponse errorResponse) {
        LogHelper.logErrorMessage(errorResponse.getMessage(), e);
        return ApiGatewayResponseGenerator.proxyJsonResponse(
                status,
                new JourneyErrorResponse(
                        JOURNEY_ERROR_PATH, status, errorResponse, e.getMessage()));
    }
}
