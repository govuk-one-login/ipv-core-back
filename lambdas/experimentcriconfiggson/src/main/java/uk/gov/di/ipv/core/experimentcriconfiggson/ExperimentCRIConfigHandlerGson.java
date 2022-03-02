package uk.gov.di.ipv.core.experimentcriconfiggson;

import com.amazonaws.services.lambda.runtime.Context;
import com.amazonaws.services.lambda.runtime.RequestHandler;
import com.amazonaws.services.lambda.runtime.events.APIGatewayProxyRequestEvent;
import com.amazonaws.services.lambda.runtime.events.APIGatewayProxyResponseEvent;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import software.amazon.awssdk.http.urlconnection.UrlConnectionHttpClient;
import software.amazon.awssdk.regions.Region;
import software.amazon.awssdk.services.ssm.SsmClient;
import software.amazon.lambda.powertools.parameters.ParamManager;
import software.amazon.lambda.powertools.parameters.SSMProvider;
import software.amazon.lambda.powertools.tracing.Tracing;
import uk.gov.di.ipv.core.experimentcriconfiggson.annotations.ExcludeFromGeneratedCoverageReport;
import uk.gov.di.ipv.core.experimentcriconfiggson.domain.CredentialIssuerConfig;
import uk.gov.di.ipv.core.experimentcriconfiggson.domain.ErrorResponse;
import uk.gov.di.ipv.core.experimentcriconfiggson.exceptions.ParseCredentialIssuerConfigException;
import uk.gov.di.ipv.core.experimentcriconfiggson.helpers.ApiGatewayResponseGenerator;

import java.net.URI;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

@ExcludeFromGeneratedCoverageReport
public class ExperimentCRIConfigHandlerGson
        implements RequestHandler<APIGatewayProxyRequestEvent, APIGatewayProxyResponseEvent> {

    public static final int LOCALHOST_PORT = 4567;
    private static final String LOCALHOST_URI = "http://localhost:" + LOCALHOST_PORT;
    private static final String IS_LOCAL = "IS_LOCAL";
    public static final String CREDENTIAL_ISSUERS_CONFIG_PARAM_PREFIX =
            "CREDENTIAL_ISSUERS_CONFIG_PARAM_PREFIX";

    private final SSMProvider ssmProvider;

    private static final Logger LOGGER =
            LoggerFactory.getLogger(ExperimentCRIConfigHandlerGson.class);

    public ExperimentCRIConfigHandlerGson() {
        if (isRunningLocally()) {
            this.ssmProvider =
                    ParamManager.getSsmProvider(
                            SsmClient.builder()
                                    .endpointOverride(URI.create(LOCALHOST_URI))
                                    .httpClient(UrlConnectionHttpClient.create())
                                    .region(Region.EU_WEST_2)
                                    .build());
        } else {
            this.ssmProvider =
                    ParamManager.getSsmProvider(
                            SsmClient.builder()
                                    .httpClient(UrlConnectionHttpClient.create())
                                    .build());
        }
    }

    @Override
    @Tracing
    public APIGatewayProxyResponseEvent handleRequest(
            APIGatewayProxyRequestEvent input, Context context) {

        try {
            List<CredentialIssuerConfig> config = getCredentialIssuersGson();
            return ApiGatewayResponseGenerator.proxyJsonResponse(200, config);
        } catch (ParseCredentialIssuerConfigException e) {
            String errorMessage =
                    String.format("Failed to load credential issuer config: %s", e.getMessage());
            LOGGER.error(errorMessage);
            return ApiGatewayResponseGenerator.proxyJsonResponse(
                    500, ErrorResponse.FAILED_TO_PARSE_CREDENTIAL_ISSUER_CONFIG);
        }
    }

    @Tracing
    private boolean isRunningLocally() {
        return Boolean.parseBoolean(System.getenv(IS_LOCAL));
    }

    @Tracing
    private List<CredentialIssuerConfig> getCredentialIssuersGson()
            throws ParseCredentialIssuerConfigException {
        Map<String, String> params =
                ssmProvider
                        .recursive()
                        .getMultiple(System.getenv(CREDENTIAL_ISSUERS_CONFIG_PARAM_PREFIX));

        Map<String, Map<String, Object>> map = new HashMap<>();
        for (Map.Entry<String, String> entry : params.entrySet()) {
            if (map.computeIfAbsent(getCriIdFromParameter(entry), k -> new HashMap<>())
                            .put(getAttributeNameFromParameter(entry), entry.getValue())
                    != null) {
                throw new ParseCredentialIssuerConfigException(
                        String.format(
                                "Duplicate parameter in Parameter Store: %s",
                                getAttributeNameFromParameter(entry)));
            }
        }

        List<CredentialIssuerConfig> configList = new ArrayList<>();

        map.forEach(
                (k, v) -> {
                    CredentialIssuerConfig credentialIssuerConfig =
                            new CredentialIssuerConfig(
                                    k,
                                    v.get("name").toString(),
                                    URI.create(v.get("tokenUrl").toString()),
                                    URI.create(v.get("credentialUrl").toString()),
                                    URI.create(v.get("authorizeUrl").toString()),
                                    v.get("ipvClientId").toString());

                    configList.add(credentialIssuerConfig);
                });

        return configList;
    }

    @Tracing
    private String getAttributeNameFromParameter(Map.Entry<String, String> parameter)
            throws ParseCredentialIssuerConfigException {
        String[] splitKey =
                getSplitKey(
                        parameter,
                        "The attribute name cannot be parsed from the parameter path %s");
        return splitKey[1];
    }

    @Tracing
    private String getCriIdFromParameter(Map.Entry<String, String> parameter)
            throws ParseCredentialIssuerConfigException {
        String[] splitKey =
                getSplitKey(
                        parameter,
                        "The credential issuer id cannot be parsed from the parameter path %s");
        return splitKey[0];
    }

    @Tracing
    private String[] getSplitKey(Map.Entry<String, String> parameter, String message)
            throws ParseCredentialIssuerConfigException {
        String[] splitKey = parameter.getKey().split("/");
        if (splitKey.length < 2) {
            String errorMessage = String.format(message, parameter.getKey());
            LOGGER.error(errorMessage);
            throw new ParseCredentialIssuerConfigException(errorMessage);
        }
        return splitKey;
    }
}
