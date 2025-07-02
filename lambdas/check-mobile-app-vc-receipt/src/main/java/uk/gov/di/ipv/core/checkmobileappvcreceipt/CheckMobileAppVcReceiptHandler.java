package uk.gov.di.ipv.core.checkmobileappvcreceipt;

import com.amazonaws.services.lambda.runtime.Context;
import com.amazonaws.services.lambda.runtime.RequestHandler;
import com.amazonaws.services.lambda.runtime.events.APIGatewayProxyRequestEvent;
import com.amazonaws.services.lambda.runtime.events.APIGatewayProxyResponseEvent;
import com.nimbusds.oauth2.sdk.util.StringUtils;
import org.apache.logging.log4j.Level;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import software.amazon.awssdk.http.HttpStatusCode;
import software.amazon.lambda.powertools.logging.Logging;
import software.amazon.lambda.powertools.metrics.Metrics;
import uk.gov.di.ipv.core.checkmobileappvcreceipt.dto.CheckMobileAppVcReceiptRequest;
import uk.gov.di.ipv.core.checkmobileappvcreceipt.exception.InvalidCheckMobileAppVcReceiptRequestException;
import uk.gov.di.ipv.core.library.annotations.ExcludeFromGeneratedCoverageReport;
import uk.gov.di.ipv.core.library.cimit.exception.CiRetrievalException;
import uk.gov.di.ipv.core.library.cimit.service.CimitService;
import uk.gov.di.ipv.core.library.criresponse.domain.AsyncCriStatus;
import uk.gov.di.ipv.core.library.criresponse.exception.InvalidCriResponseException;
import uk.gov.di.ipv.core.library.criresponse.service.CriResponseService;
import uk.gov.di.ipv.core.library.domain.ErrorResponse;
import uk.gov.di.ipv.core.library.domain.JourneyErrorResponse;
import uk.gov.di.ipv.core.library.domain.JourneyResponse;
import uk.gov.di.ipv.core.library.evcs.exception.EvcsServiceException;
import uk.gov.di.ipv.core.library.evcs.service.EvcsService;
import uk.gov.di.ipv.core.library.exceptions.CiExtractionException;
import uk.gov.di.ipv.core.library.exceptions.ConfigException;
import uk.gov.di.ipv.core.library.exceptions.CredentialParseException;
import uk.gov.di.ipv.core.library.exceptions.HttpResponseExceptionWithErrorBody;
import uk.gov.di.ipv.core.library.exceptions.IpvSessionNotFoundException;
import uk.gov.di.ipv.core.library.exceptions.MissingSecurityCheckCredential;
import uk.gov.di.ipv.core.library.exceptions.VerifiableCredentialException;
import uk.gov.di.ipv.core.library.helpers.ApiGatewayResponseGenerator;
import uk.gov.di.ipv.core.library.helpers.LogHelper;
import uk.gov.di.ipv.core.library.helpers.RequestHelper;
import uk.gov.di.ipv.core.library.service.AuditService;
import uk.gov.di.ipv.core.library.service.CimitUtilityService;
import uk.gov.di.ipv.core.library.service.ClientOAuthSessionDetailsService;
import uk.gov.di.ipv.core.library.service.ConfigService;
import uk.gov.di.ipv.core.library.service.IpvSessionService;
import uk.gov.di.ipv.core.library.useridentity.service.UserIdentityService;
import uk.gov.di.ipv.core.library.verifiablecredential.service.SessionCredentialsService;
import uk.gov.di.ipv.core.processcricallback.service.CriCheckingService;

import java.io.UncheckedIOException;
import java.util.List;

import static uk.gov.di.ipv.core.library.domain.Cri.DCMAW_ASYNC;
import static uk.gov.di.ipv.core.library.evcs.enums.EvcsVCState.PENDING_RETURN;
import static uk.gov.di.ipv.core.library.journeys.JourneyUris.JOURNEY_ERROR_PATH;

public class CheckMobileAppVcReceiptHandler
        implements RequestHandler<APIGatewayProxyRequestEvent, APIGatewayProxyResponseEvent> {
    private static final Logger LOGGER = LogManager.getLogger();
    private final ConfigService configService;
    private final IpvSessionService ipvSessionService;
    private final ClientOAuthSessionDetailsService clientOAuthSessionDetailsService;
    private final CriResponseService criResponseService;
    private final CriCheckingService criCheckingService;
    private final SessionCredentialsService sessionCredentialsService;
    private final EvcsService evcsService;

    public CheckMobileAppVcReceiptHandler(
            ConfigService configService,
            IpvSessionService ipvSessionService,
            ClientOAuthSessionDetailsService clientOAuthSessionDetailsService,
            CriResponseService criResponseService,
            CriCheckingService criCheckingService,
            SessionCredentialsService sessionCredentialsService,
            EvcsService evcsService) {
        this.configService = configService;
        this.ipvSessionService = ipvSessionService;
        this.clientOAuthSessionDetailsService = clientOAuthSessionDetailsService;
        this.criResponseService = criResponseService;
        this.criCheckingService = criCheckingService;
        this.sessionCredentialsService = sessionCredentialsService;
        this.evcsService = evcsService;
    }

    @ExcludeFromGeneratedCoverageReport
    public CheckMobileAppVcReceiptHandler() {
        configService = ConfigService.create();
        ipvSessionService = new IpvSessionService(configService);
        clientOAuthSessionDetailsService = new ClientOAuthSessionDetailsService(configService);
        criResponseService = new CriResponseService(configService);
        criCheckingService =
                new CriCheckingService(
                        configService,
                        AuditService.create(configService),
                        new UserIdentityService(configService),
                        new CimitService(configService),
                        new CimitUtilityService(configService),
                        ipvSessionService);
        sessionCredentialsService = new SessionCredentialsService(configService);
        evcsService = new EvcsService(configService);
    }

    @Override
    @Logging(clearState = true)
    @Metrics(captureColdStart = true)
    public APIGatewayProxyResponseEvent handleRequest(
            APIGatewayProxyRequestEvent input, Context context) {
        LogHelper.attachTraceId();
        LogHelper.attachComponentId(configService);

        try {
            var request = parseRequest(input);

            var journeyResponse = getJourneyResponse(request);

            if (journeyResponse != null) {
                return ApiGatewayResponseGenerator.proxyJsonResponse(
                        HttpStatusCode.OK, journeyResponse);
            }

            // Frontend will continue polling
            return ApiGatewayResponseGenerator.proxyJsonResponse(
                    HttpStatusCode.NOT_FOUND, "No VC found");
        } catch (HttpResponseExceptionWithErrorBody | VerifiableCredentialException e) {
            if (ErrorResponse.FAILED_NAME_CORRELATION.equals(e.getErrorResponse())) {
                return buildErrorResponse(
                        e, HttpStatusCode.BAD_REQUEST, e.getErrorResponse(), Level.INFO);
            }
            return buildErrorResponse(e, HttpStatusCode.BAD_REQUEST, e.getErrorResponse());
        } catch (IpvSessionNotFoundException e) {
            return buildErrorResponse(
                    e, HttpStatusCode.BAD_REQUEST, ErrorResponse.IPV_SESSION_NOT_FOUND);
        } catch (InvalidCriResponseException e) {
            return buildErrorResponse(
                    e, HttpStatusCode.INTERNAL_SERVER_ERROR, e.getErrorResponse());
        } catch (CredentialParseException e) {
            return buildErrorResponse(
                    e,
                    HttpStatusCode.INTERNAL_SERVER_ERROR,
                    ErrorResponse.FAILED_TO_PARSE_ISSUED_CREDENTIALS);
        } catch (EvcsServiceException e) {
            return buildErrorResponse(e, e.getResponseCode(), e.getErrorResponse());
        } catch (ConfigException e) {
            return buildErrorResponse(
                    e, HttpStatusCode.INTERNAL_SERVER_ERROR, ErrorResponse.FAILED_TO_PARSE_CONFIG);
        } catch (CiRetrievalException e) {
            return buildErrorResponse(
                    e,
                    HttpStatusCode.INTERNAL_SERVER_ERROR,
                    ErrorResponse.FAILED_TO_GET_STORED_CIS);
        } catch (CiExtractionException e) {
            return buildErrorResponse(
                    e,
                    HttpStatusCode.INTERNAL_SERVER_ERROR,
                    ErrorResponse.FAILED_TO_EXTRACT_CIS_FROM_VC);
        } catch (MissingSecurityCheckCredential e) {
            return buildErrorResponse(
                    e,
                    HttpStatusCode.INTERNAL_SERVER_ERROR,
                    ErrorResponse.MISSING_SECURITY_CHECK_CREDENTIAL);
        } catch (UncheckedIOException e) {
            // Temporary mitigation to force lambda instance to crash and restart by explicitly
            // exiting the program on fatal IOException - see PYIC-8220 and incident INC0014398.
            LOGGER.error("Crashing on UncheckedIOException", e);
            System.exit(1);
            return null;
        } catch (Exception e) {
            LOGGER.error(LogHelper.buildErrorMessage("Unhandled lambda exception", e));
            throw e;
        }
    }

    private CheckMobileAppVcReceiptRequest parseRequest(APIGatewayProxyRequestEvent input) {
        return new CheckMobileAppVcReceiptRequest(
                input.getHeaders().get("ipv-session-id"),
                input.getHeaders().get("ip-address"),
                input.getHeaders().get("txma-audit-encoded"),
                RequestHelper.getFeatureSet(input.getHeaders()));
    }

    private JourneyResponse getJourneyResponse(CheckMobileAppVcReceiptRequest request)
            throws IpvSessionNotFoundException,
                    HttpResponseExceptionWithErrorBody,
                    InvalidCriResponseException,
                    CredentialParseException,
                    VerifiableCredentialException,
                    ConfigException,
                    CiRetrievalException,
                    EvcsServiceException,
                    CiExtractionException,
                    MissingSecurityCheckCredential {
        // Validate callback sessions
        validateSessionId(request);

        // Get/ set session items/ config
        var ipvSessionItem = ipvSessionService.getIpvSession(request.getIpvSessionId());
        var clientOAuthSessionItem =
                clientOAuthSessionDetailsService.getClientOAuthSession(
                        ipvSessionItem.getClientOAuthSessionId());
        var userId = clientOAuthSessionItem.getUserId();
        configService.setFeatureSet(request.getFeatureSet());

        // Attach variables to logs
        LogHelper.attachGovukSigninJourneyIdToLogs(
                clientOAuthSessionItem.getGovukSigninJourneyId());
        LogHelper.attachIpvSessionIdToLogs(request.getIpvSessionId());
        LogHelper.attachFeatureSetToLogs(request.getFeatureSet());

        // Retrieve and validate cri response and vc
        var criResponseItem = criResponseService.getCriResponseItem(userId, DCMAW_ASYNC);
        if (criResponseItem == null) {
            throw new InvalidCriResponseException(ErrorResponse.CRI_RESPONSE_ITEM_NOT_FOUND);
        }

        var dcmawAsyncVc =
                evcsService
                        .getVerifiableCredentials(
                                userId, clientOAuthSessionItem.getEvcsAccessToken(), PENDING_RETURN)
                        .stream()
                        .filter(vc -> DCMAW_ASYNC.equals(vc.getCri()))
                        .findFirst();

        var asyncCriStatus =
                new AsyncCriStatus(
                        DCMAW_ASYNC,
                        criResponseItem.getStatus(),
                        dcmawAsyncVc.isEmpty(),
                        true,
                        false);

        if (asyncCriStatus.isAwaitingVc()) {
            return asyncCriStatus.getJourneyForAwaitingVc(true);
        }

        sessionCredentialsService.persistCredentials(
                List.of(dcmawAsyncVc.get()), ipvSessionItem.getIpvSessionId(), true);

        return criCheckingService.checkVcResponse(
                List.of(dcmawAsyncVc.get()),
                request.getIpAddress(),
                clientOAuthSessionItem,
                ipvSessionItem,
                sessionCredentialsService.getCredentials(ipvSessionItem.getIpvSessionId(), userId));
    }

    private void validateSessionId(CheckMobileAppVcReceiptRequest request)
            throws InvalidCheckMobileAppVcReceiptRequestException {
        var ipvSessionId = request.getIpvSessionId();

        if (StringUtils.isBlank(ipvSessionId)) {
            throw new InvalidCheckMobileAppVcReceiptRequestException(
                    ErrorResponse.MISSING_IPV_SESSION_ID);
        }
    }

    private APIGatewayProxyResponseEvent buildErrorResponse(
            Exception e, int status, ErrorResponse errorResponse, Level level) {
        LOGGER.log(level, LogHelper.buildErrorMessage(errorResponse.getMessage(), e));
        return ApiGatewayResponseGenerator.proxyJsonResponse(
                status,
                new JourneyErrorResponse(
                        JOURNEY_ERROR_PATH, status, errorResponse, e.getMessage()));
    }

    private APIGatewayProxyResponseEvent buildErrorResponse(
            Exception e, int status, ErrorResponse errorResponse) {
        return buildErrorResponse(e, status, errorResponse, Level.ERROR);
    }
}
