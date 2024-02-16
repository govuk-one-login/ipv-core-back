package uk.gov.di.ipv.core.library.pacttesthelpers;

import com.amazonaws.services.lambda.runtime.RequestHandler;
import com.amazonaws.services.lambda.runtime.events.APIGatewayProxyRequestEvent;
import com.amazonaws.services.lambda.runtime.events.APIGatewayProxyResponseEvent;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

import java.util.HashMap;
import java.util.Map;

public class Injector {

    private static final Logger LOGGER = LogManager.getLogger();

    private final RequestHandler<APIGatewayProxyRequestEvent, APIGatewayProxyResponseEvent> handler;
    private final String endpoint;

    private final String pathDescription;

    private final Map<Integer, String> pathParams;

    public Injector(
            RequestHandler<APIGatewayProxyRequestEvent, APIGatewayProxyResponseEvent> handler,
            String endpoint,
            String pathDescription) {
        this.endpoint = endpoint;
        this.handler = handler;
        this.pathDescription = pathDescription;
        this.pathParams = new HashMap<>();
        this.findPathParams();
    }

    public RequestHandler<APIGatewayProxyRequestEvent, APIGatewayProxyResponseEvent> getHandler() {
        return handler;
    }

    public String getEndpoint() {
        return endpoint;
    }

    public Map<Integer, String> getPathParams() {
        return this.pathParams;
    }

    private void findPathParams() {
        String[] arr = pathDescription.split("/");
        for (int i = 0; i < arr.length; i++) {
            if (arr[i].charAt(0) == '{') {
                pathParams.put(i, arr[i].substring(1, arr.length));
                LOGGER.info("added path param : " + pathParams.get(i) + " with key: " + i);
            }
        }
    }
}
