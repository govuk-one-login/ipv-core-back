package uk.gov.di.ipv.core.processcricallback;

import com.amazonaws.services.lambda.runtime.Context;
import com.amazonaws.services.lambda.runtime.RequestHandler;
import com.amazonaws.services.lambda.runtime.events.APIGatewayProxyRequestEvent;
import com.amazonaws.services.lambda.runtime.events.APIGatewayProxyResponseEvent;
import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
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
import uk.gov.di.ipv.core.library.criapiservice.CriApiService;
import uk.gov.di.ipv.core.library.criapiservice.exception.CriApiException;
import uk.gov.di.ipv.core.library.cristoringservice.CriStoringService;
import uk.gov.di.ipv.core.library.domain.ErrorResponse;
import uk.gov.di.ipv.core.library.domain.JourneyErrorResponse;
import uk.gov.di.ipv.core.library.domain.JourneyResponse;
import uk.gov.di.ipv.core.library.domain.VerifiableCredential;
import uk.gov.di.ipv.core.library.dto.CriCallbackRequest;
import uk.gov.di.ipv.core.library.exceptions.ConfigException;
import uk.gov.di.ipv.core.library.exceptions.HttpResponseExceptionWithErrorBody;
import uk.gov.di.ipv.core.library.exceptions.SqsException;
import uk.gov.di.ipv.core.library.exceptions.UnrecognisedVotException;
import uk.gov.di.ipv.core.library.exceptions.VerifiableCredentialException;
import uk.gov.di.ipv.core.library.helpers.ApiGatewayResponseGenerator;
import uk.gov.di.ipv.core.library.helpers.LogHelper;
import uk.gov.di.ipv.core.library.helpers.RequestHelper;
import uk.gov.di.ipv.core.library.helpers.SecureTokenHelper;
import uk.gov.di.ipv.core.library.helpers.StepFunctionHelpers;
import uk.gov.di.ipv.core.library.kmses256signer.KmsEs256SignerFactory;
import uk.gov.di.ipv.core.library.persistence.item.ClientOAuthSessionItem;
import uk.gov.di.ipv.core.library.persistence.item.CriOAuthSessionItem;
import uk.gov.di.ipv.core.library.persistence.item.IpvSessionItem;
import uk.gov.di.ipv.core.library.service.AuditService;
import uk.gov.di.ipv.core.library.service.CiMitService;
import uk.gov.di.ipv.core.library.service.CiMitUtilityService;
import uk.gov.di.ipv.core.library.service.ClientOAuthSessionDetailsService;
import uk.gov.di.ipv.core.library.service.ConfigService;
import uk.gov.di.ipv.core.library.service.CriOAuthSessionService;
import uk.gov.di.ipv.core.library.service.CriResponseService;
import uk.gov.di.ipv.core.library.service.IpvSessionService;
import uk.gov.di.ipv.core.library.service.SsmConfigService;
import uk.gov.di.ipv.core.library.service.UserIdentityService;
import uk.gov.di.ipv.core.library.verifiablecredential.domain.VerifiableCredentialResponse;
import uk.gov.di.ipv.core.library.verifiablecredential.domain.VerifiableCredentialStatus;
import uk.gov.di.ipv.core.library.verifiablecredential.helpers.VcHelper;
import uk.gov.di.ipv.core.library.verifiablecredential.service.SessionCredentialsService;
import uk.gov.di.ipv.core.library.verifiablecredential.validator.VerifiableCredentialValidator;
import uk.gov.di.ipv.core.processcricallback.exception.InvalidCriCallbackRequestException;
import uk.gov.di.ipv.core.processcricallback.exception.ParseCriCallbackRequestException;
import uk.gov.di.ipv.core.processcricallback.service.CriCheckingService;

import java.time.Clock;
import java.util.Collections;
import java.util.List;

import static uk.gov.di.ipv.core.library.domain.Cri.DCMAW;
import static uk.gov.di.ipv.core.library.journeyuris.JourneyUris.JOURNEY_ERROR_PATH;
import static uk.gov.di.ipv.core.library.journeyuris.JourneyUris.JOURNEY_NOT_FOUND_PATH;

public class ProcessCriCallbackHandler
        implements RequestHandler<APIGatewayProxyRequestEvent, APIGatewayProxyResponseEvent> {
    private static final Logger LOGGER = LogManager.getLogger();
    private static final ObjectMapper OBJECT_MAPPER = new ObjectMapper();
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
    private final VerifiableCredentialValidator verifiableCredentialValidator;
    private final ClientOAuthSessionDetailsService clientOAuthSessionDetailsService;
    private final AuditService auditService;

    @SuppressWarnings("java:S107") // Methods should not have too many parameters
    public ProcessCriCallbackHandler(
            ConfigService configService,
            IpvSessionService ipvSessionService,
            CriOAuthSessionService criOAuthSessionService,
            VerifiableCredentialValidator verifiableCredentialValidator,
            ClientOAuthSessionDetailsService clientOAuthSessionDetailsService,
            CriApiService criApiService,
            CriStoringService criStoringService,
            CriCheckingService criCheckingService,
            AuditService auditService) {
        this.configService = configService;
        this.criApiService = criApiService;
        this.criStoringService = criStoringService;
        this.criCheckingService = criCheckingService;
        this.ipvSessionService = ipvSessionService;
        this.criOAuthSessionService = criOAuthSessionService;
        this.verifiableCredentialValidator = verifiableCredentialValidator;
        this.clientOAuthSessionDetailsService = clientOAuthSessionDetailsService;
        this.auditService = auditService;
        VcHelper.setConfigService(this.configService);
    }

    @ExcludeFromGeneratedCoverageReport
    public ProcessCriCallbackHandler() {
        configService = new SsmConfigService();
        ipvSessionService = new IpvSessionService(configService);
        criOAuthSessionService = new CriOAuthSessionService(configService);
        verifiableCredentialValidator = new VerifiableCredentialValidator(configService);
        clientOAuthSessionDetailsService = new ClientOAuthSessionDetailsService(configService);
        auditService = new AuditService(AuditService.getSqsClients(), configService);

        var sessionCredentialsService = new SessionCredentialsService(configService);
        var ciMitService = new CiMitService(configService);

        criApiService =
                new CriApiService(
                        configService,
                        new KmsEs256SignerFactory(),
                        SecureTokenHelper.getInstance(),
                        Clock.systemDefaultZone());
        criCheckingService =
                new CriCheckingService(
                        configService,
                        auditService,
                        new UserIdentityService(configService),
                        ciMitService,
                        new CiMitUtilityService(configService),
                        sessionCredentialsService);
        criStoringService =
                new CriStoringService(
                        configService,
                        auditService,
                        new CriResponseService(configService),
                        sessionCredentialsService,
                        ciMitService);

        VcHelper.setConfigService(configService);
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
        } catch (HttpResponseExceptionWithErrorBody | VerifiableCredentialException e) {
            return buildErrorResponse(e, e.getResponseCode(), e.getErrorResponse());
        } catch (JsonProcessingException | SqsException e) {
            return buildErrorResponse(
                    e,
                    HttpStatus.SC_INTERNAL_SERVER_ERROR,
                    ErrorResponse.FAILED_TO_SEND_AUDIT_EVENT);
        } catch (UnrecognisedVotException e) {
            return buildErrorResponse(
                    e,
                    HttpStatus.SC_INTERNAL_SERVER_ERROR,
                    ErrorResponse.FAILED_TO_PARSE_ISSUED_CREDENTIALS);
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
        } catch (CriApiException e) {
            if (DCMAW.equals(callbackRequest.getCredentialIssuer())
                    && e.getHttpStatusCode() == HTTPResponse.SC_NOT_FOUND) {
                LOGGER.error(
                        LogHelper.buildErrorMessage(
                                "404 received from DCMAW CRI", e.getErrorResponse().getMessage()));
                return ApiGatewayResponseGenerator.proxyJsonResponse(
                        HttpStatus.SC_OK, JOURNEY_NOT_FOUND);
            }
            return buildErrorResponse(e, e.getHttpStatusCode(), e.getErrorResponse());
        } finally {
            auditService.awaitAuditEvents();
        }
    }

    private CriCallbackRequest parseCallbackRequest(APIGatewayProxyRequestEvent input)
            throws ParseCriCallbackRequestException {
        try {
            var callbackRequest =
                    OBJECT_MAPPER.readValue(input.getBody(), CriCallbackRequest.class);
            callbackRequest.setIpvSessionId(input.getHeaders().get("ipv-session-id"));
            callbackRequest.setFeatureSet(RequestHelper.getFeatureSet(input.getHeaders()));
            callbackRequest.setIpAddress(input.getHeaders().get("ip-address"));
            callbackRequest.setDeviceInformation(input.getHeaders().get("txma-audit-encoded"));
            return callbackRequest;
        } catch (JsonProcessingException e) {
            throw new ParseCriCallbackRequestException(e);
        }
    }

    private JourneyResponse getJourneyResponse(CriCallbackRequest callbackRequest)
            throws SqsException, JsonProcessingException, HttpResponseExceptionWithErrorBody,
                    ConfigException, CiRetrievalException, CriApiException,
                    VerifiableCredentialException, CiPostMitigationsException, CiPutException,
                    InvalidCriCallbackRequestException, UnrecognisedVotException {
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
        LogHelper.attachCriIdToLogs(callbackRequest.getCredentialIssuer());
        LogHelper.attachComponentId(configService);

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
                        accessToken, callbackRequest.getCredentialIssuer(), criOAuthSessionItem);
        var vcs =
                validateAndStoreResponse(
                        callbackRequest,
                        vcResponse,
                        clientOAuthSessionItem,
                        criOAuthSessionItem,
                        ipvSessionItem);

        return criCheckingService.checkVcResponse(
                vcs, callbackRequest, clientOAuthSessionItem, ipvSessionItem);
    }

    private List<VerifiableCredential> validateAndStoreResponse(
            CriCallbackRequest callbackRequest,
            VerifiableCredentialResponse vcResponse,
            ClientOAuthSessionItem clientOAuthSessionItem,
            CriOAuthSessionItem criOAuthSessionItem,
            IpvSessionItem ipvSessionItem)
            throws VerifiableCredentialException, JsonProcessingException, SqsException,
                    InvalidCriCallbackRequestException, CiPutException, CiPostMitigationsException,
                    UnrecognisedVotException {
        if (VerifiableCredentialStatus.PENDING.equals(vcResponse.getCredentialStatus())) {
            criCheckingService.validatePendingVcResponse(vcResponse, clientOAuthSessionItem);
            criStoringService.recordCriResponse(callbackRequest, clientOAuthSessionItem);

            return Collections.emptyList();
        } else {
            if (criOAuthSessionItem == null) {
                // We should never get here due to earlier null checks.
                // This is to satisfy compile time warning
                throw new InvalidCriCallbackRequestException(ErrorResponse.INVALID_OAUTH_STATE);
            }

            var criConfig = configService.getOauthCriConfig(criOAuthSessionItem);

            var vcs =
                    verifiableCredentialValidator.parseAndValidate(
                            clientOAuthSessionItem.getUserId(),
                            callbackRequest.getCredentialIssuer(),
                            vcResponse.getVerifiableCredentials(),
                            criConfig.getSigningKey(),
                            criConfig.getComponentId());

            criStoringService.storeVcs(
                    callbackRequest.getCredentialIssuer(),
                    callbackRequest.getIpAddress(),
                    callbackRequest.getDeviceInformation(),
                    vcs,
                    clientOAuthSessionItem,
                    ipvSessionItem);

            ipvSessionService.updateIpvSession(ipvSessionItem);

            return vcs;
        }
    }

    private APIGatewayProxyResponseEvent buildErrorResponse(
            Exception e, int status, ErrorResponse errorResponse) {
        LOGGER.error(LogHelper.buildErrorMessage(errorResponse.getMessage(), e));
        return ApiGatewayResponseGenerator.proxyJsonResponse(
                status,
                new JourneyErrorResponse(
                        JOURNEY_ERROR_PATH, status, errorResponse, e.getMessage()));
    }
}
