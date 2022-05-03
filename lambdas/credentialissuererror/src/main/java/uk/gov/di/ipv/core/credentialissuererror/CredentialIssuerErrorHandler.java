package uk.gov.di.ipv.core.credentialissuererror;

import com.amazonaws.services.lambda.runtime.Context;
import com.amazonaws.services.lambda.runtime.RequestHandler;
import com.amazonaws.services.lambda.runtime.events.APIGatewayProxyRequestEvent;
import com.amazonaws.services.lambda.runtime.events.APIGatewayProxyResponseEvent;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import uk.gov.di.ipv.core.library.annotations.ExcludeFromGeneratedCoverageReport;
import uk.gov.di.ipv.core.library.domain.JourneyResponse;
import uk.gov.di.ipv.core.library.domain.UserStates;
import uk.gov.di.ipv.core.library.dto.CredentialIssuerErrorDto;
import uk.gov.di.ipv.core.library.helpers.ApiGatewayResponseGenerator;
import uk.gov.di.ipv.core.library.helpers.RequestHelper;
import uk.gov.di.ipv.core.library.persistence.item.IpvSessionItem;
import uk.gov.di.ipv.core.library.service.ConfigurationService;
import uk.gov.di.ipv.core.library.service.IpvSessionService;

public class CredentialIssuerErrorHandler
        implements RequestHandler<APIGatewayProxyRequestEvent, APIGatewayProxyResponseEvent> {

    private static final Logger LOGGER =
            LoggerFactory.getLogger(CredentialIssuerErrorHandler.class.getName());

    private static final String NEXT_JOURNEY_STEP_URI = "/journey/next";

    private final IpvSessionService ipvSessionService;
    private final ConfigurationService configurationService;

    public CredentialIssuerErrorHandler(
            IpvSessionService ipvSessionService, ConfigurationService configurationService) {
        this.ipvSessionService = ipvSessionService;
        this.configurationService = configurationService;
    }

    @ExcludeFromGeneratedCoverageReport
    public CredentialIssuerErrorHandler() {
        this.configurationService = new ConfigurationService();
        this.ipvSessionService = new IpvSessionService(configurationService);
    }

    @Override
    public APIGatewayProxyResponseEvent handleRequest(
            APIGatewayProxyRequestEvent input, Context context) {
        CredentialIssuerErrorDto credentialIssuerErrorDto =
                RequestHelper.convertRequest(input, CredentialIssuerErrorDto.class);

        LOGGER.error(
                "An error occurred with the {} cri",
                credentialIssuerErrorDto.getCredentialIssuerId());
        LOGGER.error("Error code: {}", credentialIssuerErrorDto.getError());
        LOGGER.error(credentialIssuerErrorDto.getErrorDescription());

        IpvSessionItem ipvSessionItem =
                ipvSessionService.getIpvSession(credentialIssuerErrorDto.getIpvSessionId());
        ipvSessionItem.setUserState(UserStates.CRI_ERROR.toString());

        ipvSessionService.updateIpvSession(ipvSessionItem);

        JourneyResponse journeyResponse = new JourneyResponse(NEXT_JOURNEY_STEP_URI);

        return ApiGatewayResponseGenerator.proxyJsonResponse(200, journeyResponse);
    }
}
