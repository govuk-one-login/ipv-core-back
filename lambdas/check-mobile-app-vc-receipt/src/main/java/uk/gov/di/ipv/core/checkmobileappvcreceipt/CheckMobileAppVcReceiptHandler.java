package uk.gov.di.ipv.core.checkmobileappvcreceipt;

import com.amazonaws.services.lambda.runtime.Context;
import com.amazonaws.services.lambda.runtime.RequestHandler;
import com.amazonaws.services.lambda.runtime.events.APIGatewayProxyRequestEvent;
import com.amazonaws.services.lambda.runtime.events.APIGatewayProxyResponseEvent;
import com.nimbusds.oauth2.sdk.util.StringUtils;
import org.apache.http.HttpStatus;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import software.amazon.lambda.powertools.logging.Logging;
import software.amazon.lambda.powertools.tracing.Tracing;
import uk.gov.di.ipv.core.checkmobileappvcreceipt.dto.CheckMobileAppVcReceiptRequest;
import uk.gov.di.ipv.core.checkmobileappvcreceipt.exception.InvalidCheckMobileAppVcReceiptRequestException;
import uk.gov.di.ipv.core.library.annotations.ExcludeFromGeneratedCoverageReport;
import uk.gov.di.ipv.core.library.cimit.exception.CiRetrievalException;
import uk.gov.di.ipv.core.library.domain.AsyncCriStatus;
import uk.gov.di.ipv.core.library.domain.ErrorResponse;
import uk.gov.di.ipv.core.library.domain.JourneyErrorResponse;
import uk.gov.di.ipv.core.library.domain.JourneyResponse;
import uk.gov.di.ipv.core.library.exception.EvcsServiceException;
import uk.gov.di.ipv.core.library.exception.InvalidCriResponseException;
import uk.gov.di.ipv.core.library.exceptions.ConfigException;
import uk.gov.di.ipv.core.library.exceptions.CredentialParseException;
import uk.gov.di.ipv.core.library.exceptions.HttpResponseExceptionWithErrorBody;
import uk.gov.di.ipv.core.library.exceptions.IpvSessionNotFoundException;
import uk.gov.di.ipv.core.library.exceptions.VerifiableCredentialException;
import uk.gov.di.ipv.core.library.helpers.ApiGatewayResponseGenerator;
import uk.gov.di.ipv.core.library.helpers.LogHelper;
import uk.gov.di.ipv.core.library.helpers.RequestHelper;
import uk.gov.di.ipv.core.library.service.AuditService;
import uk.gov.di.ipv.core.library.service.CimitService;
import uk.gov.di.ipv.core.library.service.CimitUtilityService;
import uk.gov.di.ipv.core.library.service.ClientOAuthSessionDetailsService;
import uk.gov.di.ipv.core.library.service.ConfigService;
import uk.gov.di.ipv.core.library.service.CriResponseService;
import uk.gov.di.ipv.core.library.service.EvcsService;
import uk.gov.di.ipv.core.library.service.IpvSessionService;
import uk.gov.di.ipv.core.library.service.UserIdentityService;
import uk.gov.di.ipv.core.library.verifiablecredential.service.SessionCredentialsService;
import uk.gov.di.ipv.core.processcricallback.service.CriCheckingService;

import java.util.List;

import static uk.gov.di.ipv.core.library.domain.Cri.DCMAW_ASYNC;
import static uk.gov.di.ipv.core.library.enums.EvcsVCState.PENDING_RETURN;
import static uk.gov.di.ipv.core.library.journeys.JourneyUris.JOURNEY_ERROR_PATH;

public class CheckMobileAppVcReceiptHandler
        implements RequestHandler<APIGatewayProxyRequestEvent, APIGatewayProxyResponseEvent> {
    private static final Logger LOGGER = LogManager.getLogger();
    private final ConfigService configService;
    private final IpvSessionService ipvSessionService;
    private final ClientOAuthSessionDetailsService clientOAuthSessionDetailsService;
    private final CriResponseService criResponseService;
    private final CriCheckingService criCheckingService;
    private final EvcsService evcsService;
    private final SessionCredentialsService sessionCredentialsService;

    public CheckMobileAppVcReceiptHandler(
            ConfigService configService,
            IpvSessionService ipvSessionService,
            ClientOAuthSessionDetailsService clientOAuthSessionDetailsService,
            CriResponseService criResponseService,
            CriCheckingService criCheckingService,
            EvcsService evcsService,
            SessionCredentialsService sessionCredentialsService) {
        this.configService = configService;
        this.ipvSessionService = ipvSessionService;
        this.clientOAuthSessionDetailsService = clientOAuthSessionDetailsService;
        this.criResponseService = criResponseService;
        this.criCheckingService = criCheckingService;
        this.evcsService = evcsService;
        this.sessionCredentialsService = sessionCredentialsService;
    }

    @ExcludeFromGeneratedCoverageReport
    public CheckMobileAppVcReceiptHandler() {
        configService = ConfigService.create();
        ipvSessionService = new IpvSessionService(configService);
        clientOAuthSessionDetailsService = new ClientOAuthSessionDetailsService(configService);
        criResponseService = new CriResponseService(configService);

        sessionCredentialsService = new SessionCredentialsService(configService);
        var cimitService = new CimitService(configService);
        criCheckingService =
                new CriCheckingService(
                        configService,
                        AuditService.create(configService),
                        new UserIdentityService(configService),
                        cimitService,
                        new CimitUtilityService(configService),
                        sessionCredentialsService,
                        ipvSessionService);
        evcsService = new EvcsService(configService);
    }

    @Override
    @Tracing
    @Logging(clearState = true)
    public APIGatewayProxyResponseEvent handleRequest(
            APIGatewayProxyRequestEvent input, Context context) {
        try {
            var request = parseRequest(input);

            var journeyResponse = getJourneyResponse(request);

            if (journeyResponse != null) {
                return ApiGatewayResponseGenerator.proxyJsonResponse(
                        HttpStatus.SC_OK, journeyResponse);
            }

            // Frontend will continue polling
            return ApiGatewayResponseGenerator.proxyResponse(HttpStatus.SC_NOT_FOUND);
        } catch (HttpResponseExceptionWithErrorBody | VerifiableCredentialException e) {
            return buildErrorResponse(e, HttpStatus.SC_BAD_REQUEST, e.getErrorResponse());
        } catch (IpvSessionNotFoundException e) {
            return buildErrorResponse(
                    e, HttpStatus.SC_BAD_REQUEST, ErrorResponse.IPV_SESSION_NOT_FOUND);
        } catch (InvalidCriResponseException e) {
            return buildErrorResponse(e, HttpStatus.SC_INTERNAL_SERVER_ERROR, e.getErrorResponse());
        } catch (CredentialParseException e) {
            return buildErrorResponse(
                    e,
                    HttpStatus.SC_INTERNAL_SERVER_ERROR,
                    ErrorResponse.FAILED_TO_PARSE_ISSUED_CREDENTIALS);
        } catch (EvcsServiceException e) {
            return buildErrorResponse(e, e.getResponseCode(), e.getErrorResponse());
        } catch (ConfigException e) {
            return buildErrorResponse(
                    e, HttpStatus.SC_INTERNAL_SERVER_ERROR, ErrorResponse.FAILED_TO_PARSE_CONFIG);
        } catch (CiRetrievalException e) {
            return buildErrorResponse(
                    e, HttpStatus.SC_INTERNAL_SERVER_ERROR, ErrorResponse.FAILED_TO_GET_STORED_CIS);
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
                    EvcsServiceException {
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
        LogHelper.attachComponentId(configService);

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
                        DCMAW_ASYNC, criResponseItem.getStatus(), dcmawAsyncVc.isEmpty(), true);

        if (asyncCriStatus.isAwaitingVc()) {
            return asyncCriStatus.getJourneyForAwaitingVc(true);
        }

        sessionCredentialsService.persistCredentials(
                List.of(dcmawAsyncVc.get()), ipvSessionItem.getIpvSessionId(), false);

        return criCheckingService.checkVcResponse(
                List.of(dcmawAsyncVc.get()),
                request.getIpAddress(),
                clientOAuthSessionItem,
                ipvSessionItem);
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
            Exception e, int status, ErrorResponse errorResponse) {
        LOGGER.error(LogHelper.buildErrorMessage(errorResponse.getMessage(), e));
        return ApiGatewayResponseGenerator.proxyJsonResponse(
                status,
                new JourneyErrorResponse(
                        JOURNEY_ERROR_PATH, status, errorResponse, e.getMessage()));
    }
}
