package uk.gov.di.ipv.core.library.pacttesthelpers;

import com.amazonaws.services.lambda.runtime.Context;
import com.amazonaws.services.lambda.runtime.RequestHandler;
import com.amazonaws.services.lambda.runtime.events.APIGatewayProxyRequestEvent;
import com.amazonaws.services.lambda.runtime.events.APIGatewayProxyResponseEvent;
import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.JWSSigner;
import com.nimbusds.jose.util.Base64URL;
import com.nimbusds.jwt.JWT;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.JWTParser;
import com.nimbusds.jwt.SignedJWT;
import com.sun.net.httpserver.Headers;
import com.sun.net.httpserver.HttpExchange;
import com.sun.net.httpserver.HttpHandler;
import org.apache.commons.io.IOUtils;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.mockito.Mockito;

import java.io.IOException;
import java.io.OutputStream;
import java.io.UnsupportedEncodingException;
import java.net.URI;
import java.net.URLDecoder;
import java.nio.charset.StandardCharsets;
import java.sql.Date;
import java.text.ParseException;
import java.time.LocalDate;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.TreeMap;
import java.util.UUID;
import java.util.stream.Collectors;

class PreLambdaHandler implements HttpHandler {

    private static final Logger LOGGER = LogManager.getLogger();
    private final RequestHandler<APIGatewayProxyRequestEvent, APIGatewayProxyResponseEvent> handler;
    private final Map<Integer, String> pathParamsFromInjector;

    private JWSSigner signer;

    public PreLambdaHandler(Injector injector, JWSSigner signer) {
        this.handler = injector.getHandler();
        this.pathParamsFromInjector = injector.getPathParams();
        this.signer = signer;
    }

    @Override
    public void handle(HttpExchange exchange) throws IOException {

        try {
            APIGatewayProxyRequestEvent request = translateRequest(exchange);

            Context context = Mockito.mock(Context.class);

            APIGatewayProxyResponseEvent response = this.handler.handleRequest(request, context);

            LOGGER.info("Response has been returned lambda handler");
            LOGGER.info(response.getBody());

            translateResponse(response, exchange);

        } catch (Exception e) {
            LOGGER.error("Error caught in handler and thrown up to server");
            LOGGER.error(e.getMessage(), e);
            String err = "Some error occurred";
            exchange.sendResponseHeaders(500, err.length());
            try (OutputStream os = exchange.getResponseBody()) {
                os.write(err.getBytes());
            }
        }
    }

    private Map<String, String> getHeaderMap(Headers h) {
        return h.keySet().stream()
                .collect(
                        Collectors.toMap(
                                key -> key,
                                key -> String.join(", ", h.get(key)),
                                (existing, replacement) -> existing));
    }

    private Map<String, String> getPathParameters(String requestURL) {
        HashMap<String, String> pathParams = new HashMap<>();
        String[] pathArr = requestURL.split("/");
        if (!pathParamsFromInjector.isEmpty() && pathArr.length > 1) {
            pathParamsFromInjector
                    .keySet()
                    .forEach(key -> pathParams.put(pathParamsFromInjector.get(key), pathArr[key]));
        }
        return pathParams;
    }

    public static Map<String, String> getQueryStringParams(URI url)
            throws UnsupportedEncodingException {
        Map<String, String> query_pairs = new HashMap<>();
        String query = url.getQuery();
        String[] pairs = query.split("&");
        for (String pair : pairs) {
            int idx = pair.indexOf("=");
            query_pairs.put(
                    URLDecoder.decode(pair.substring(0, idx), "UTF-8"),
                    URLDecoder.decode(pair.substring(idx + 1), "UTF-8"));
        }
        return query_pairs;
    }

    private APIGatewayProxyRequestEvent translateRequest(HttpExchange request) throws IOException {

        String requestBody = IOUtils.toString(request.getRequestBody(), StandardCharsets.UTF_8);
        LOGGER.info("BODY FROM ORIGINAL REQUEST");
        LOGGER.info(requestBody);

        String requestPath = request.getRequestURI().getPath();

        LOGGER.info(requestPath);

        Headers requestHeaders = request.getRequestHeaders();

        String requestId = UUID.randomUUID().toString();

        APIGatewayProxyRequestEvent apiGatewayProxyRequestEvent =
                new APIGatewayProxyRequestEvent()
                        .withBody(requestBody)
                        .withHeaders(getHeaderMap(requestHeaders))
                        .withHttpMethod(request.getRequestMethod())
                        .withPathParameters(getPathParameters(requestPath))
                        .withRequestContext(
                                new APIGatewayProxyRequestEvent.ProxyRequestContext()
                                        .withRequestId(requestId));
        String requestQuery = request.getRequestURI().getQuery();
        LOGGER.info("query retrieved: " + requestQuery);

        if (requestQuery != null) {
            apiGatewayProxyRequestEvent.setQueryStringParameters(
                    getQueryStringParams(request.getRequestURI()));
        }

        LOGGER.info("BODY FROM AG FORMED REQUEST");
        LOGGER.info(apiGatewayProxyRequestEvent.getBody());

        return apiGatewayProxyRequestEvent;
    }

    private void translateResponse(APIGatewayProxyResponseEvent response, HttpExchange exchange)
            throws IOException, JOSEException {
        Integer statusCode = response.getStatusCode();

        Headers serverResponseHeaders = exchange.getResponseHeaders();
        response.getHeaders().forEach(serverResponseHeaders::set);

        if (!response.getBody().isEmpty()) {
            LOGGER.info("getting response body");

            String body = response.getBody();
            try {
                JWT jwt = JWTParser.parse(body);

                LocalDate futureDate = LocalDate.of(2099, 1, 1);
                Date nbf = Date.valueOf(futureDate);

                JWTClaimsSet claimsSet = jwt.getJWTClaimsSet();
                Object vcClaim = claimsSet.getClaim("vc");
                Map<String, Object> vc = (Map<String, Object>) vcClaim;
                Map<String, Object> credentialSubject =
                        (Map<String, Object>) vc.get("credentialSubject");
                List<Object> evidence = (List<Object>) vc.get("evidence");
                List<Object> sortedEvidence =
                        evidence.stream().sorted().collect(Collectors.toList());
                TreeMap<Object, Object> sortedCredentialSubject = new TreeMap<>(credentialSubject);

                vc.put("credentialSubject", sortedCredentialSubject);
                vc.put("evidence", sortedEvidence);

                SignedJWT signedJWT = amendClaimSet(jwt, nbf, vc, claimsSet);

                body = signedJWT.serialize();
            } catch (ParseException e) {

                // Continue
            }

            exchange.sendResponseHeaders(statusCode, body.length());
            try (OutputStream os = exchange.getResponseBody()) {
                os.write(body.getBytes());
            }
        }
    }

    private SignedJWT amendClaimSet(
            JWT jwt, Date nbf, Map<String, Object> vc, JWTClaimsSet claimsSet)
            throws JOSEException, ParseException, JsonProcessingException {

        JWTClaimsSet modifiedClaimsSet =
                new JWTClaimsSet.Builder(claimsSet).notBeforeTime(nbf).claim("vc", vc).build();
        SignedJWT signedJWT = new SignedJWT((JWSHeader) jwt.getHeader(), modifiedClaimsSet);
        signedJWT.sign(signer);

        TreeMap<String, Object> test = new TreeMap<>();
        test.put("typ", jwt.getHeader().getType().getType());
        test.put("alg", jwt.getHeader().getAlgorithm().getName());

        Base64URL jwtHeader = Base64URL.encode(new ObjectMapper().writeValueAsString(test));
        String[] serialize = signedJWT.serialize().split("\\.");

        SignedJWT signedJWTNew =
                new SignedJWT(
                        jwtHeader, Base64URL.from(serialize[1]), Base64URL.from(serialize[2]));

        return signedJWTNew;
    }
}
