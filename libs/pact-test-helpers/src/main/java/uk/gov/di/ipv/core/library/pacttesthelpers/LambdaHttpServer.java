package uk.gov.di.ipv.core.library.pacttesthelpers;

import com.amazonaws.services.lambda.runtime.Context;
import com.amazonaws.services.lambda.runtime.RequestHandler;
import com.amazonaws.services.lambda.runtime.events.APIGatewayProxyRequestEvent;
import com.amazonaws.services.lambda.runtime.events.APIGatewayProxyResponseEvent;
import com.sun.net.httpserver.Headers;
import com.sun.net.httpserver.HttpExchange;
import com.sun.net.httpserver.HttpHandler;
import com.sun.net.httpserver.HttpServer;
import org.apache.commons.io.IOUtils;
import org.mockito.Mockito;

import java.io.IOException;
import java.io.OutputStream;
import java.io.UnsupportedEncodingException;
import java.net.InetSocketAddress;
import java.net.URLDecoder;
import java.nio.charset.StandardCharsets;
import java.util.HashMap;
import java.util.Map;
import java.util.UUID;
import java.util.concurrent.Executors;
import java.util.stream.Collectors;

public class LambdaHttpServer {
    private final HttpServer server;

    public LambdaHttpServer(
            RequestHandler<APIGatewayProxyRequestEvent, APIGatewayProxyResponseEvent> handler,
            String path,
            int port)
            throws IOException {
        server = HttpServer.create(new InetSocketAddress(port), 0);
        server.createContext(path, new LambdaHandlerWrapper(handler));
        server.setExecutor(Executors.newCachedThreadPool()); // creates a default executor
    }

    public void startServer() {
        server.start();
    }

    public void stopServer() {
        server.stop(0);
    }

    // This class converts between HTTP requests and responses and AWS's APIGatewayProxyRequestEvent
    // and APIGatewayProxyResponseEvent
    private class LambdaHandlerWrapper implements HttpHandler {

        private final RequestHandler<APIGatewayProxyRequestEvent, APIGatewayProxyResponseEvent>
                handler;

        public LambdaHandlerWrapper(
                RequestHandler<APIGatewayProxyRequestEvent, APIGatewayProxyResponseEvent> handler) {
            this.handler = handler;
        }

        @Override
        public void handle(HttpExchange exchange) throws IOException {

            try {
                APIGatewayProxyRequestEvent request = translateRequest(exchange);
                Context context = Mockito.mock(Context.class);

                APIGatewayProxyResponseEvent response =
                        this.handler.handleRequest(request, context);

                translateResponse(response, exchange);
            } catch (Exception e) {
                String error = "Some error occurred";
                exchange.sendResponseHeaders(500, error.length());
                try (OutputStream os = exchange.getResponseBody()) {
                    os.write(error.getBytes());
                }
            }
        }

        private APIGatewayProxyRequestEvent translateRequest(HttpExchange request)
                throws IOException {

            String requestBody = IOUtils.toString(request.getRequestBody(), StandardCharsets.UTF_8);

            Headers requestHeaders = request.getRequestHeaders();

            String requestId = UUID.randomUUID().toString();

            APIGatewayProxyRequestEvent apiGatewayProxyRequestEvent =
                    new APIGatewayProxyRequestEvent()
                            .withBody(requestBody)
                            .withHeaders(getHeaderMap(requestHeaders))
                            .withHttpMethod(request.getRequestMethod())
                            .withRequestContext(
                                    new APIGatewayProxyRequestEvent.ProxyRequestContext()
                                            .withRequestId(requestId));

            String requestQuery = request.getRequestURI().getQuery();

            if (requestQuery != null) {
                apiGatewayProxyRequestEvent.setQueryStringParameters(
                        parseQueryParams(requestQuery));
            }

            return apiGatewayProxyRequestEvent;
        }

        private Map<String, String> getHeaderMap(Headers headers) {
            return headers.keySet().stream()
                    .collect(
                            Collectors.toMap(
                                    key -> key,
                                    key -> String.join(", ", headers.get(key)),
                                    (existing, replacement) -> existing));
        }

        public static Map<String, String> parseQueryParams(String query)
                throws UnsupportedEncodingException {
            Map<String, String> queryPairs = new HashMap<>();
            String[] pairs = query.split("&");
            for (String pair : pairs) {
                int idx = pair.indexOf("=");
                queryPairs.put(
                        URLDecoder.decode(pair.substring(0, idx), "UTF-8"),
                        URLDecoder.decode(pair.substring(idx + 1), "UTF-8"));
            }
            return queryPairs;
        }

        private void translateResponse(APIGatewayProxyResponseEvent response, HttpExchange exchange)
                throws IOException {
            Integer statusCode = response.getStatusCode();

            Headers serverResponseHeaders = exchange.getResponseHeaders();
            response.getHeaders().forEach(serverResponseHeaders::set);

            if (!response.getBody().isEmpty()) {
                String body = response.getBody();
                exchange.sendResponseHeaders(statusCode, body.length());
                try (OutputStream os = exchange.getResponseBody()) {
                    os.write(body.getBytes());
                }
            }
        }
    }
}
