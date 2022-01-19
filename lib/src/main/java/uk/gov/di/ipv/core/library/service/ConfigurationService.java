package uk.gov.di.ipv.core.library.service;

import com.fasterxml.jackson.databind.ObjectMapper;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import software.amazon.awssdk.regions.Region;
import software.amazon.awssdk.services.ssm.SsmClient;
import software.amazon.lambda.powertools.parameters.ParamManager;
import software.amazon.lambda.powertools.parameters.SSMProvider;
import uk.gov.di.ipv.core.library.dto.CredentialIssuerConfig;
import uk.gov.di.ipv.core.library.exceptions.ParseCredentialIssuerConfigException;

import java.net.URI;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Map.Entry;
import java.util.Optional;
import java.util.stream.Collectors;

public class ConfigurationService {

    public static final int LOCALHOST_PORT = 4567;
    private static final String LOCALHOST_URI = "http://localhost:" + LOCALHOST_PORT;
    private static final long DEFAULT_BEARER_TOKEN_TTL_IN_SECS = 3600L;
    private static final String IS_LOCAL = "IS_LOCAL";

    private static final Logger LOGGER = LoggerFactory.getLogger(ConfigurationService.class);

    private final SSMProvider ssmProvider;
    private final ObjectMapper objectMapper = new ObjectMapper();

    public ConfigurationService(SSMProvider ssmProvider) {
        this.ssmProvider = ssmProvider;
    }

    public ConfigurationService() {
        if (isRunningLocally()) {
            this.ssmProvider =
                    ParamManager.getSsmProvider(
                            SsmClient.builder()
                                    .endpointOverride(URI.create(LOCALHOST_URI))
                                    .region(Region.EU_WEST_2)
                                    .build());
        } else {
            this.ssmProvider = ParamManager.getSsmProvider();
        }
    }

    public SSMProvider getSsmProvider() {
        return ssmProvider;
    }

    public boolean isRunningLocally() {
        return Boolean.parseBoolean(System.getenv(IS_LOCAL));
    }

    public String getAuthCodesTableName() {
        return System.getenv("AUTH_CODES_TABLE_NAME");
    }

    public String getUserIssuedCredentialTableName() {
        return System.getenv("USER_ISSUED_CREDENTIALS_TABLE_NAME");
    }

    public String getAccessTokensTableName() {
        return System.getenv("ACCESS_TOKENS_TABLE_NAME");
    }

    public String getIpvSessionTableName() {
        return System.getenv("IPV_SESSIONS_TABLE_NAME");
    }

    public long getBearerAccessTokenTtl() {
        return Optional.ofNullable(System.getenv("BEARER_TOKEN_TTL"))
                .map(Long::valueOf)
                .orElse(DEFAULT_BEARER_TOKEN_TTL_IN_SECS);
    }

    public CredentialIssuerConfig getCredentialIssuer(String credentialIssuerId) {
        Map<String, String> result =
                ssmProvider.getMultiple(
                        String.format(
                                "/%s/ipv/core/credentialIssuers/%s",
                                System.getenv("ENVIRONMENT"), credentialIssuerId));
        CredentialIssuerConfig credentialIssuerConfig =
                new ObjectMapper().convertValue(result, CredentialIssuerConfig.class);
        credentialIssuerConfig.setId(credentialIssuerId);
        return credentialIssuerConfig;
    }

    public List<CredentialIssuerConfig> getCredentialIssuers()
            throws ParseCredentialIssuerConfigException {
        Map<String, String> params =
                ssmProvider
                        .recursive()
                        .getMultiple(
                                String.format(
                                        "/%s/ipv/core/credentialIssuers",
                                        System.getenv("ENVIRONMENT")));

        Map<String, Map<String, Object>> map = new HashMap<>();
        for (Entry<String, String> stringStringEntry : params.entrySet()) {
            if (map.computeIfAbsent(getCriIdFromParameter(stringStringEntry), k -> new HashMap<>())
                            .put(
                                    getAttributeNameFromParameter(stringStringEntry),
                                    stringStringEntry.getValue())
                    != null) {
                throw new IllegalStateException("Duplicate key");
            }
        }

        List<CredentialIssuerConfig> credentialIssuersConfig =
                map.values().stream()
                        .map(
                                config ->
                                        objectMapper.convertValue(
                                                config, CredentialIssuerConfig.class))
                        .collect(Collectors.toList());

        return credentialIssuersConfig;
    }

    private String getAttributeNameFromParameter(Entry<String, String> parameter)
            throws ParseCredentialIssuerConfigException {
        String[] splitKey = parameter.getKey().split("/");
        if (splitKey.length < 2) {
            String errorMessage =
                    String.format(
                            "The attribute name cannot be parsed from the parameter path %s",
                            parameter.getKey());
            LOGGER.error(String.format(errorMessage));
            throw new ParseCredentialIssuerConfigException(errorMessage);
        }
        return splitKey[1];
    }

    private String getCriIdFromParameter(Entry<String, String> parameter)
            throws ParseCredentialIssuerConfigException {
        String[] splitKey = parameter.getKey().split("/");

        if (splitKey.length < 2) {
            String errorMessage =
                    String.format(
                            "The credential issuer id cannot be parsed from the parameter path %s",
                            parameter.getKey());
            LOGGER.error(String.format(errorMessage));
            throw new ParseCredentialIssuerConfigException(errorMessage);
        }
        return splitKey[0];
    }
}
