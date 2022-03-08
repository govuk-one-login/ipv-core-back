package uk.gov.di.ipv.core.journeyengine;

import com.amazonaws.services.lambda.runtime.Context;
import com.amazonaws.services.lambda.runtime.RequestHandler;
import com.amazonaws.services.lambda.runtime.events.APIGatewayProxyRequestEvent;
import com.amazonaws.services.lambda.runtime.events.APIGatewayProxyResponseEvent;
import software.amazon.lambda.powertools.tracing.Tracing;

import java.util.logging.Logger;

public class JourneyEngineHandler
        implements RequestHandler<APIGatewayProxyRequestEvent, APIGatewayProxyResponseEvent> {

    private static final Logger LOGGER = Logger.getLogger(JourneyEngineHandler.class.getName());
    private static final String JOURNEY_ID_PARAM = "journeyId";

    @Override
    @Tracing
    public APIGatewayProxyResponseEvent handleRequest(
            APIGatewayProxyRequestEvent input, Context context) {
        LOGGER.info("Hello world!");

        String journeyId = input.getPathParameters().get(JOURNEY_ID_PARAM);
        LOGGER.info(journeyId);

        return null;
    }
}
