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
import uk.gov.di.ipv.core.library.domain.Cri;
import uk.gov.di.ipv.core.library.domain.ErrorResponse;
import uk.gov.di.ipv.core.library.domain.JourneyErrorResponse;
import uk.gov.di.ipv.core.library.domain.JourneyResponse;
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
import uk.gov.di.ipv.core.library.service.IpvSessionService;
import uk.gov.di.ipv.core.library.service.UserIdentityService;
import uk.gov.di.ipv.core.library.service.domain.AsyncCriStatus;
import uk.gov.di.ipv.core.library.service.exception.InvalidCriResponseException;
import uk.gov.di.ipv.core.library.verifiablecredential.service.SessionCredentialsService;
import uk.gov.di.ipv.core.library.verifiablecredential.service.VerifiableCredentialService;
import uk.gov.di.ipv.core.processcricallback.service.CriCheckingService;

import java.util.List;

import static uk.gov.di.ipv.core.library.journeys.JourneyUris.JOURNEY_ABANDON_PATH;
import static uk.gov.di.ipv.core.library.journeys.JourneyUris.JOURNEY_ERROR_PATH;

public class CheckMobileAppVcReceiptHandler
        implements RequestHandler<APIGatewayProxyRequestEvent, APIGatewayProxyResponseEvent> {
    private static final Logger LOGGER = LogManager.getLogger();
    private static final JourneyResponse JOURNEY_ABANDON =
            new JourneyResponse(JOURNEY_ABANDON_PATH);
    private static final JourneyResponse JOURNEY_ERROR = new JourneyResponse(JOURNEY_ERROR_PATH);
    private final ConfigService configService;
    private final IpvSessionService ipvSessionService;
    private final ClientOAuthSessionDetailsService clientOAuthSessionDetailsService;
    private final CriResponseService criResponseService;
    private final VerifiableCredentialService verifiableCredentialService;
    private final CriCheckingService criCheckingService;

    public CheckMobileAppVcReceiptHandler(
            ConfigService configService,
            IpvSessionService ipvSessionService,
            ClientOAuthSessionDetailsService clientOAuthSessionDetailsService,
            CriResponseService criResponseService,
            VerifiableCredentialService verifiableCredentialService,
            CriCheckingService criCheckingService) {
        this.configService = configService;
        this.ipvSessionService = ipvSessionService;
        this.clientOAuthSessionDetailsService = clientOAuthSessionDetailsService;
        this.criResponseService = criResponseService;
        this.verifiableCredentialService = verifiableCredentialService;
        this.criCheckingService = criCheckingService;
    }

    @ExcludeFromGeneratedCoverageReport
    public CheckMobileAppVcReceiptHandler() {
        configService = ConfigService.create();
        ipvSessionService = new IpvSessionService(configService);
        clientOAuthSessionDetailsService = new ClientOAuthSessionDetailsService(configService);
        criResponseService = new CriResponseService(configService);
        verifiableCredentialService = new VerifiableCredentialService(configService);

        var sessionCredentialsService = new SessionCredentialsService(configService);
        var cimitService = new CimitService(configService);

        criCheckingService =
                new CriCheckingService(
                        configService,
                        AuditService.create(configService),
                        new UserIdentityService(configService),
                        cimitService,
                        new CimitUtilityService(configService),
                        sessionCredentialsService);
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
            throws IpvSessionNotFoundException, HttpResponseExceptionWithErrorBody,
                    InvalidCriResponseException, CredentialParseException,
                    VerifiableCredentialException, ConfigException, CiRetrievalException {
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
        var criResponseItem = criResponseService.getCriResponseItem(userId, Cri.DCMAW_ASYNC);
        if (criResponseItem == null) {
            throw new InvalidCriResponseException(ErrorResponse.CRI_RESPONSE_ITEM_NOT_FOUND);
        }

        var vc = verifiableCredentialService.getVc(userId, Cri.DCMAW_ASYNC.getId());
        var isVcNull = vc == null;
        var asyncCriStatus =
                new AsyncCriStatus(
                        Cri.DCMAW_ASYNC, null, criResponseItem.getStatus(), isVcNull, !isVcNull);
        if (asyncCriStatus.isAwaitingVc()) {
            return asyncCriStatus.getJourneyForAwaitingVc(true);
        }

        return criCheckingService.checkVcResponse(
                List.of(vc), request.getIpAddress(), clientOAuthSessionItem, ipvSessionItem);
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
