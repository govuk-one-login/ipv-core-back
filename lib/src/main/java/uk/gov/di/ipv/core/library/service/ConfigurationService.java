package uk.gov.di.ipv.core.library.service;

import com.fasterxml.jackson.databind.ObjectMapper;
import software.amazon.awssdk.regions.Region;
import software.amazon.awssdk.services.ssm.SsmClient;
import software.amazon.lambda.powertools.parameters.ParamManager;
import software.amazon.lambda.powertools.parameters.SSMProvider;
import uk.gov.di.ipv.core.library.dto.CredentialIssuerConfig;

import java.net.URI;
import java.util.Arrays;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Map;
import java.util.Optional;
import java.util.Set;

public class ConfigurationService {

    public static final int LOCALHOST_PORT = 4567;
    private static final String LOCALHOST_URI = "http://localhost:" + LOCALHOST_PORT;
    private static final long DEFAULT_BEARER_TOKEN_TTL_IN_SECS = 3600L;
    private static final String IS_LOCAL = "IS_LOCAL";

    private final SSMProvider ssmProvider;

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
        Map<String, String> result = ssmProvider.getMultiple(String.format("/%s/ipv/core/credentialIssuers/%s", System.getenv("ENVIRONMENT"), credentialIssuerId));
        CredentialIssuerConfig credentialIssuerConfig = new ObjectMapper().convertValue(result, CredentialIssuerConfig.class);
        credentialIssuerConfig.setId(credentialIssuerId);
        return credentialIssuerConfig;
    }

    public Set<CredentialIssuerConfig> getCredentialIssuers() {
        Map<String, String> result = ssmProvider.recursive().getMultiple(String.format("/%s/ipv/core/credentialIssuers", System.getenv("ENVIRONMENT")));

        Map<String, CredentialIssuerConfig> credentialIssuers = new HashMap<>();
        result.forEach((key, value) -> {
            Optional<String> credentialIssuerId = Arrays.stream(key.split("/")).findFirst();
            credentialIssuerId.ifPresent(id -> {
                if (!credentialIssuers.containsKey(id)) {
                    credentialIssuers.put(id, getCredentialIssuer(id));
                }
            });

        });
        return new HashSet<>(credentialIssuers.values());
    }
}
