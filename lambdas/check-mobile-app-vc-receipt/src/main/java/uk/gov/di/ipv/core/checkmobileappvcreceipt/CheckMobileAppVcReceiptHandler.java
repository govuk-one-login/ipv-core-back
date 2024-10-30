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
import uk.gov.di.ipv.core.library.domain.Cri;
import uk.gov.di.ipv.core.library.domain.ErrorResponse;
import uk.gov.di.ipv.core.library.exceptions.ClientOauthSessionNotFoundException;
import uk.gov.di.ipv.core.library.exceptions.CredentialParseException;
import uk.gov.di.ipv.core.library.exceptions.IpvSessionNotFoundException;
import uk.gov.di.ipv.core.library.helpers.ApiGatewayResponseGenerator;
import uk.gov.di.ipv.core.library.helpers.LogHelper;
import uk.gov.di.ipv.core.library.helpers.RequestHelper;
import uk.gov.di.ipv.core.library.service.ClientOAuthSessionDetailsService;
import uk.gov.di.ipv.core.library.service.ConfigService;
import uk.gov.di.ipv.core.library.service.CriResponseService;
import uk.gov.di.ipv.core.library.service.IpvSessionService;
import uk.gov.di.ipv.core.library.service.exception.InvalidCriResponseException;
import uk.gov.di.ipv.core.library.verifiablecredential.service.VerifiableCredentialService;

import static uk.gov.di.ipv.core.library.helpers.LogHelper.buildErrorMessage;

public class CheckMobileAppVcReceiptHandler
        implements RequestHandler<APIGatewayProxyRequestEvent, APIGatewayProxyResponseEvent> {
    private static final Logger LOGGER = LogManager.getLogger();
    private final ConfigService configService;
    private final IpvSessionService ipvSessionService;
    private final ClientOAuthSessionDetailsService clientOAuthSessionDetailsService;
    private final CriResponseService criResponseService;
    private final VerifiableCredentialService verifiableCredentialService;

    public CheckMobileAppVcReceiptHandler(
            ConfigService configService,
            IpvSessionService ipvSessionService,
            ClientOAuthSessionDetailsService clientOAuthSessionDetailsService,
            CriResponseService criResponseService,
            VerifiableCredentialService verifiableCredentialService) {
        this.configService = configService;
        this.ipvSessionService = ipvSessionService;
        this.clientOAuthSessionDetailsService = clientOAuthSessionDetailsService;
        this.criResponseService = criResponseService;
        this.verifiableCredentialService = verifiableCredentialService;
    }

    @ExcludeFromGeneratedCoverageReport
    public CheckMobileAppVcReceiptHandler() {
        configService = ConfigService.create();
        ipvSessionService = new IpvSessionService(configService);
        clientOAuthSessionDetailsService = new ClientOAuthSessionDetailsService(configService);
        criResponseService = new CriResponseService(configService);
        verifiableCredentialService = new VerifiableCredentialService(configService);
    }

    @Override
    @Tracing
    @Logging(clearState = true)
    public APIGatewayProxyResponseEvent handleRequest(
            APIGatewayProxyRequestEvent input, Context context) {
        try {
            var request = parseRequest(input);

            var status = getStatus(request);

            return ApiGatewayResponseGenerator.proxyResponse(status);
        } catch (InvalidCheckMobileAppVcReceiptRequestException e) {
            LOGGER.info(buildErrorMessage(e.getErrorResponse()));
            return ApiGatewayResponseGenerator.proxyResponse(HttpStatus.SC_BAD_REQUEST);
        } catch (IpvSessionNotFoundException e) {
            LOGGER.info(buildErrorMessage(ErrorResponse.IPV_SESSION_NOT_FOUND));
            return ApiGatewayResponseGenerator.proxyResponse(HttpStatus.SC_BAD_REQUEST);
        } catch (ClientOauthSessionNotFoundException e) {
            LOGGER.info(buildErrorMessage(e.getErrorResponse()));
            return ApiGatewayResponseGenerator.proxyResponse(HttpStatus.SC_BAD_REQUEST);
        } catch (InvalidCriResponseException e) {
            LOGGER.info(buildErrorMessage(e.getErrorResponse()));
            return ApiGatewayResponseGenerator.proxyResponse(HttpStatus.SC_INTERNAL_SERVER_ERROR);
        } catch (CredentialParseException e) {
            LOGGER.info(buildErrorMessage(ErrorResponse.FAILED_TO_PARSE_ISSUED_CREDENTIALS));
            return ApiGatewayResponseGenerator.proxyResponse(HttpStatus.SC_INTERNAL_SERVER_ERROR);
        }
    }

    private CheckMobileAppVcReceiptRequest parseRequest(APIGatewayProxyRequestEvent input) {
        return new CheckMobileAppVcReceiptRequest(
                input.getHeaders().get("ipv-session-id"),
                input.getHeaders().get("ip-address"),
                input.getHeaders().get("txma-audit-encoded"),
                RequestHelper.getFeatureSet(input.getHeaders()));
    }

    private int getStatus(CheckMobileAppVcReceiptRequest request)
            throws InvalidCheckMobileAppVcReceiptRequestException, IpvSessionNotFoundException,
                    ClientOauthSessionNotFoundException, InvalidCriResponseException,
                    CredentialParseException {
        // Validate sessions
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

        // Retrieve and check cri response
        var criResponse = criResponseService.getCriResponseItem(userId, Cri.DCMAW_ASYNC);

        if (criResponse == null) {
            return HttpStatus.SC_INTERNAL_SERVER_ERROR;
        }

        if (!CriResponseService.STATUS_PENDING.equals(criResponse.getStatus())
                || verifiableCredentialService.getVc(userId, Cri.DCMAW_ASYNC.toString()) != null) {
            return HttpStatus.SC_OK;
        }

        return HttpStatus.SC_NOT_FOUND;
    }

    private void validateSessionId(CheckMobileAppVcReceiptRequest request)
            throws InvalidCheckMobileAppVcReceiptRequestException {
        var ipvSessionId = request.getIpvSessionId();

        if (StringUtils.isBlank(ipvSessionId)) {
            throw new InvalidCheckMobileAppVcReceiptRequestException(
                    ErrorResponse.MISSING_IPV_SESSION_ID);
        }
    }
}
