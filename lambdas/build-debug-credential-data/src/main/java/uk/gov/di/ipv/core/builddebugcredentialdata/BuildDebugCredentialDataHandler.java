package uk.gov.di.ipv.core.builddebugcredentialdata;

import com.amazonaws.services.lambda.runtime.Context;
import com.amazonaws.services.lambda.runtime.RequestHandler;
import com.amazonaws.services.lambda.runtime.events.APIGatewayProxyRequestEvent;
import com.amazonaws.services.lambda.runtime.events.APIGatewayProxyResponseEvent;
import org.apache.http.HttpStatus;
import software.amazon.lambda.powertools.logging.Logging;
import software.amazon.lambda.powertools.tracing.Tracing;
import uk.gov.di.ipv.core.library.annotations.ExcludeFromGeneratedCoverageReport;
import uk.gov.di.ipv.core.library.dto.ClientSessionDetailsDto;
import uk.gov.di.ipv.core.library.exceptions.HttpResponseExceptionWithErrorBody;
import uk.gov.di.ipv.core.library.helpers.ApiGatewayResponseGenerator;
import uk.gov.di.ipv.core.library.helpers.LogHelper;
import uk.gov.di.ipv.core.library.helpers.RequestHelper;
import uk.gov.di.ipv.core.library.persistence.item.IpvSessionItem;
import uk.gov.di.ipv.core.library.service.ConfigurationService;
import uk.gov.di.ipv.core.library.service.IpvSessionService;
import uk.gov.di.ipv.core.library.service.UserIdentityService;

public class BuildDebugCredentialDataHandler
        implements RequestHandler<APIGatewayProxyRequestEvent, APIGatewayProxyResponseEvent> {

    private final UserIdentityService userIdentityService;
    private final ConfigurationService configurationService;
    private final IpvSessionService ipvSessionService;

    public BuildDebugCredentialDataHandler(
            UserIdentityService userIdentityService,
            ConfigurationService configurationService,
            IpvSessionService ipvSessionService) {
        this.userIdentityService = userIdentityService;
        this.configurationService = configurationService;
        this.ipvSessionService = ipvSessionService;
    }

    @ExcludeFromGeneratedCoverageReport
    public BuildDebugCredentialDataHandler() {
        this.configurationService = new ConfigurationService();
        this.userIdentityService = new UserIdentityService(configurationService);
        this.ipvSessionService = new IpvSessionService(configurationService);
    }

    @Override
    @Tracing
    @Logging(clearState = true)
    public APIGatewayProxyResponseEvent handleRequest(
            APIGatewayProxyRequestEvent input, Context context) {
        LogHelper.attachComponentIdToLogs();
        try {
            String ipvSessionId = RequestHelper.getIpvSessionId(input);
            IpvSessionItem ipvSessionItem = ipvSessionService.getIpvSession(ipvSessionId);
            ClientSessionDetailsDto clientSessionDetailsDto =
                    ipvSessionItem.getClientSessionDetails();
            LogHelper.attachGovukSigninJourneyIdToLogs(
                    clientSessionDetailsDto.getGovukSigninJourneyId());
            return ApiGatewayResponseGenerator.proxyJsonResponse(
                    HttpStatus.SC_OK,
                    userIdentityService.getUserIssuedDebugCredentials(
                            clientSessionDetailsDto.getUserId()));
        } catch (HttpResponseExceptionWithErrorBody e) {
            return ApiGatewayResponseGenerator.proxyJsonResponse(
                    e.getResponseCode(), e.getErrorBody());
        }
    }
}
