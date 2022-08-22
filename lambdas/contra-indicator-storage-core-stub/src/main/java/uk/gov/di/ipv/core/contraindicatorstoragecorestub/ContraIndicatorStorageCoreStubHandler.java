package uk.gov.di.ipv.core.contraindicatorstoragecorestub;

import com.amazonaws.services.lambda.AWSLambda;
import com.amazonaws.services.lambda.AWSLambdaClientBuilder;
import com.amazonaws.services.lambda.model.InvokeRequest;
import com.amazonaws.services.lambda.model.InvokeResult;
import com.amazonaws.services.lambda.runtime.Context;
import com.amazonaws.services.lambda.runtime.RequestHandler;
import com.amazonaws.services.lambda.runtime.events.APIGatewayProxyRequestEvent;
import com.amazonaws.services.lambda.runtime.events.APIGatewayProxyResponseEvent;
import com.github.mustachejava.DefaultMustacheFactory;
import com.github.mustachejava.Mustache;
import com.github.mustachejava.MustacheFactory;
import com.google.gson.Gson;
import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JOSEObjectType;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.crypto.ECDSASigner;
import com.nimbusds.jose.jwk.ECKey;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import org.apache.http.HttpHeaders;
import org.apache.http.HttpStatus;
import org.apache.http.entity.ContentType;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import software.amazon.lambda.powertools.logging.Logging;
import software.amazon.lambda.powertools.tracing.Tracing;
import uk.gov.di.ipv.core.contraindicatorstoragecorestub.domain.ContraIndicatorItem;
import uk.gov.di.ipv.core.contraindicatorstoragecorestub.domain.GetCiRequest;
import uk.gov.di.ipv.core.contraindicatorstoragecorestub.domain.GetCiResponse;
import uk.gov.di.ipv.core.contraindicatorstoragecorestub.domain.PutCiRequest;
import uk.gov.di.ipv.core.library.annotations.ExcludeFromGeneratedCoverageReport;
import uk.gov.di.ipv.core.library.helpers.RequestHelper;

import java.io.CharArrayWriter;
import java.io.UnsupportedEncodingException;
import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.text.ParseException;
import java.time.Instant;
import java.util.ArrayList;
import java.util.Date;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.UUID;

@ExcludeFromGeneratedCoverageReport
public class ContraIndicatorStorageCoreStubHandler
        implements RequestHandler<APIGatewayProxyRequestEvent, APIGatewayProxyResponseEvent> {

    private static final Gson gson = new Gson();
    private static final Logger LOGGER = LogManager.getLogger();
    private static final MustacheFactory mf = new DefaultMustacheFactory();
    private static final String EC_PRIVATE_KEY_JWK =
            "{\"kty\":\"EC\",\"d\":\"OXt0P05ZsQcK7eYusgIPsqZdaBCIJiW4imwUtnaAthU\",\"crv\":\"P-256\",\"x\":\"E9ZzuOoqcVU4pVB9rpmTzezjyOPRlOmPGJHKi8RSlIM\",\"y\":\"KlTMZthHZUkYz5AleTQ8jff0TJiS3q2OB9L5Fw4xA04\"}";

    public static final String AUDIENCE = "https://ipv-core.example.com";
    public static final String CI = "ci";
    public static final String CI_STORAGE_GET_LAMBDA_ARN = "CI_STORAGE_GET_LAMBDA_ARN";
    public static final String CI_STORAGE_PUT_LAMBDA_ARN = "CI_STORAGE_PUT_LAMBDA_ARN";
    public static final String CONTRA_INDICATORS = "contraIndicators";
    public static final String CONTRA_INDICATORS_FORM_INPUT = "contra-indicators";
    public static final String ERROR = "error";
    public static final String EVIDENCE = "evidence";
    public static final String IDENTITY_CHECK = "IdentityCheck";
    public static final String ISSUER = "https://some-cri.example.com";
    public static final String PATH = "path";
    public static final String SCORE = "score";
    public static final String TXN = "txn";
    public static final String TYPE = "type";
    public static final String USER_ID = "userId";
    public static final String USER_ID_FORM_INPUT = "user-id";
    public static final String VC = "vc";

    private final AWSLambda lambdaClient;

    public ContraIndicatorStorageCoreStubHandler() {
        this.lambdaClient = AWSLambdaClientBuilder.defaultClient();
    }

    public ContraIndicatorStorageCoreStubHandler(AWSLambda lambdaClient) {
        this.lambdaClient = lambdaClient;
    }

    @Override
    @Tracing
    @Logging(clearState = true)
    public APIGatewayProxyResponseEvent handleRequest(
            APIGatewayProxyRequestEvent input, Context context) {
        APIGatewayProxyResponseEvent response;
        switch (input.getHttpMethod()) {
            case "GET":
                response = handleGet(input);
                break;
            case "POST":
                try {
                    response = handlePost(input);
                } catch (Exception e) {
                    LOGGER.error("Exception thrown when handling post", e);
                    response = new APIGatewayProxyResponseEvent().withStatusCode(500);
                }
                break;
            default:
                throw new IllegalArgumentException(
                        String.format("Unsupported HTTP method: %s", input.getHttpMethod()));
        }

        return response;
    }

    private APIGatewayProxyResponseEvent handleGet(APIGatewayProxyRequestEvent input) {
        APIGatewayProxyResponseEvent response = new APIGatewayProxyResponseEvent();
        response.setHeaders(Map.of(HttpHeaders.CONTENT_TYPE, ContentType.TEXT_HTML.getMimeType()));

        String userId = null;
        Map<String, String> queryStringParameters = input.getQueryStringParameters();
        if (queryStringParameters != null) {
            userId = queryStringParameters.get(USER_ID);
        }

        List<ContraIndicatorItem> contraIndicators = new ArrayList<>();
        if (userId != null && !userId.equals("")) {
            InvokeResult invokeResult = invokeGetLambda(userId);
            GetCiResponse getCiResponse =
                    gson.fromJson(
                            new String(invokeResult.getPayload().array(), StandardCharsets.UTF_8),
                            GetCiResponse.class);
            LOGGER.info("getCiResponse: {}", getCiResponse);
            if (getCiResponse.getContraIndicators() != null) {
                contraIndicators.addAll(getCiResponse.getContraIndicators());
            }
        }

        Map<String, Object> templateMap = new HashMap<>();
        templateMap.put(CONTRA_INDICATORS, contraIndicators);
        templateMap.put(USER_ID, userId);
        templateMap.put(PATH, input.getRequestContext().getPath());

        LOGGER.info("templateMap: {}", templateMap);

        Mustache mustache = mf.compile("template.mustache");
        CharArrayWriter renderedTemplate = new CharArrayWriter();
        mustache.execute(renderedTemplate, templateMap);
        renderedTemplate.flush();

        response.setBody(renderedTemplate.toString());
        return response;
    }

    private APIGatewayProxyResponseEvent handlePost(APIGatewayProxyRequestEvent input)
            throws ParseException, JOSEException, UnsupportedEncodingException {
        APIGatewayProxyResponseEvent response = new APIGatewayProxyResponseEvent();

        Map<String, String> formInput = RequestHelper.parseRequestBody(input.getBody());
        String userId = formInput.get(USER_ID_FORM_INPUT);
        String[] contraIndicators = formInput.get(CONTRA_INDICATORS_FORM_INPUT).split(",");

        InvokeResult lambdaResponse = invokePutLambda(createVCSignedJwt(userId, contraIndicators));
        String responsePayload =
                new String(lambdaResponse.getPayload().array(), StandardCharsets.UTF_8);

        if (lambdaResponse.getStatusCode() != HttpStatus.SC_OK
                || lambdaResponse.getFunctionError() != null) {
            LOGGER.error("Lambda execution failed");
            LOGGER.error(lambdaResponse.getStatusCode());
            LOGGER.error(lambdaResponse.getFunctionError());
            LOGGER.error(responsePayload);
            response.setStatusCode(500);
            response.setBody(
                    gson.toJson(
                            Map.of(
                                    ERROR,
                                    String.format(
                                            "lambda invoke failed '%s'",
                                            lambdaResponse.getFunctionError()))));
        } else {
            LOGGER.info("Lambda execution succeeded");
            LOGGER.info(lambdaResponse.getStatusCode());
            LOGGER.info(responsePayload);
            response.setStatusCode(302);
            response.setHeaders(Map.of(HttpHeaders.LOCATION, buildRedirectUrl(input, userId)));
        }

        return response;
    }

    private SignedJWT createVCSignedJwt(String userId, String[] contraIndicators)
            throws ParseException, JOSEException {
        Map<String, Object> evidence = new HashMap<>();
        evidence.put(SCORE, 0);
        evidence.put(TXN, UUID.randomUUID());
        evidence.put(TYPE, IDENTITY_CHECK);

        if (contraIndicators.length > 0) {
            evidence.put(CI, contraIndicators);
        }

        Instant now = Instant.now();
        JWTClaimsSet claimsSet =
                new JWTClaimsSet.Builder()
                        .subject(userId)
                        .issuer(ISSUER)
                        .audience(AUDIENCE)
                        .notBeforeTime(new Date(now.toEpochMilli()))
                        .expirationTime(new Date(now.plusSeconds(7200L).toEpochMilli()))
                        .claim(VC, Map.of(EVIDENCE, List.of(evidence)))
                        .build();

        JWSHeader header =
                new JWSHeader.Builder(JWSAlgorithm.ES256).type(JOSEObjectType.JWT).build();
        SignedJWT signedJWT = new SignedJWT(header, claimsSet);
        signedJWT.sign(new ECDSASigner(ECKey.parse(EC_PRIVATE_KEY_JWK)));
        return signedJWT;
    }

    private InvokeResult invokePutLambda(SignedJWT vcSignedJwt) {
        PutCiRequest putCiRequest =
                new PutCiRequest(UUID.randomUUID().toString(), vcSignedJwt.serialize());

        InvokeRequest lambdaRequest =
                new InvokeRequest()
                        .withFunctionName(System.getenv(CI_STORAGE_PUT_LAMBDA_ARN))
                        .withPayload(gson.toJson(putCiRequest));

        return lambdaClient.invoke(lambdaRequest);
    }

    private InvokeResult invokeGetLambda(String userId) {
        GetCiRequest getCiRequest = new GetCiRequest(UUID.randomUUID().toString(), userId);

        InvokeRequest lambdaRequest =
                new InvokeRequest()
                        .withFunctionName(System.getenv(CI_STORAGE_GET_LAMBDA_ARN))
                        .withPayload(gson.toJson(getCiRequest));

        return lambdaClient.invoke(lambdaRequest);
    }

    private String buildRedirectUrl(APIGatewayProxyRequestEvent input, String userId)
            throws UnsupportedEncodingException {
        return String.format(
                "https://%s%s?userId=%s",
                input.getHeaders().get(HttpHeaders.HOST),
                input.getRequestContext().getPath(),
                URLEncoder.encode(userId, StandardCharsets.UTF_8.toString()));
    }
}
