package uk.gov.di.ipv.core.library.service;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import software.amazon.awssdk.http.urlconnection.UrlConnectionHttpClient;
import software.amazon.awssdk.regions.Region;
import software.amazon.awssdk.services.secretsmanager.SecretsManagerClient;
import software.amazon.awssdk.services.secretsmanager.model.DecryptionFailureException;
import software.amazon.awssdk.services.secretsmanager.model.InternalServiceErrorException;
import software.amazon.awssdk.services.secretsmanager.model.InvalidParameterException;
import software.amazon.awssdk.services.secretsmanager.model.InvalidRequestException;
import software.amazon.awssdk.services.secretsmanager.model.ResourceNotFoundException;
import software.amazon.awssdk.services.ssm.SsmClient;
import software.amazon.lambda.powertools.parameters.ParamManager;
import software.amazon.lambda.powertools.parameters.SSMProvider;
import software.amazon.lambda.powertools.parameters.SecretsProvider;
import uk.gov.di.ipv.core.library.config.ConfigurationVariable;
import uk.gov.di.ipv.core.library.config.EnvironmentVariable;
import uk.gov.di.ipv.core.library.domain.ContraIndicatorScore;
import uk.gov.di.ipv.core.library.dto.CredentialIssuerConfig;

import java.net.URI;
import java.util.Arrays;
import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;

import static java.time.temporal.ChronoUnit.MINUTES;
import static uk.gov.di.ipv.core.library.config.EnvironmentVariable.BEARER_TOKEN_TTL;
import static uk.gov.di.ipv.core.library.config.EnvironmentVariable.CREDENTIAL_ISSUERS_CONFIG_PARAM_PREFIX;
import static uk.gov.di.ipv.core.library.config.EnvironmentVariable.ENVIRONMENT;
import static uk.gov.di.ipv.core.library.config.EnvironmentVariable.IS_LOCAL;
import static uk.gov.di.ipv.core.library.config.EnvironmentVariable.SIGNING_KEY_ID_PARAM;

public class ConfigService {

    public static final int LOCALHOST_PORT = 4567;
    private static final String LOCALHOST_URI = "http://localhost:" + LOCALHOST_PORT;
    private static final long DEFAULT_BEARER_TOKEN_TTL_IN_SECS = 3600L;
    private static final String CLIENT_REDIRECT_URL_SEPARATOR = ",";
    private static final String API_KEY = "apiKey";
    private static final Logger LOGGER = LogManager.getLogger();
    private final SSMProvider ssmProvider;
    private final SecretsProvider secretsProvider;
    private final ObjectMapper objectMapper = new ObjectMapper();

    public ConfigService(SSMProvider ssmProvider, SecretsProvider secretsProvider) {
        this.ssmProvider = ssmProvider;
        this.secretsProvider = secretsProvider;
    }

    public ConfigService() {
        if (isRunningLocally()) {
            this.ssmProvider =
                    ParamManager.getSsmProvider(
                            SsmClient.builder()
                                    .endpointOverride(URI.create(LOCALHOST_URI))
                                    .httpClient(UrlConnectionHttpClient.create())
                                    .region(Region.EU_WEST_2)
                                    .build());

            this.secretsProvider =
                    ParamManager.getSecretsProvider(
                            SecretsManagerClient.builder()
                                    .endpointOverride(URI.create(LOCALHOST_URI))
                                    .httpClient(UrlConnectionHttpClient.create())
                                    .region(Region.EU_WEST_2)
                                    .build());
        } else {
            this.ssmProvider =
                    ParamManager.getSsmProvider(
                                    SsmClient.builder()
                                            .httpClient(UrlConnectionHttpClient.create())
                                            .build())
                            .defaultMaxAge(3, MINUTES);

            this.secretsProvider =
                    ParamManager.getSecretsProvider(
                                    SecretsManagerClient.builder()
                                            .httpClient(UrlConnectionHttpClient.create())
                                            .build())
                            .defaultMaxAge(3, MINUTES);
        }
    }

    public SSMProvider getSsmProvider() {
        return ssmProvider;
    }

    public String getEnvironmentVariable(EnvironmentVariable environmentVariable) {
        return System.getenv(environmentVariable.name());
    }

    public String getSsmParameter(String path) {
        return ssmProvider.get(path);
    }

    public String getSsmParameter(ConfigurationVariable configurationVariable) {
        return ssmProvider.get(
                String.format(
                        configurationVariable.getValue(), getEnvironmentVariable(ENVIRONMENT)));
    }

    // do we add another getSsm to pass in the active connection

    public String getSsmParameter(ConfigurationVariable configurationVariable, String clientId) {
        return ssmProvider.get(
                String.format(
                        configurationVariable.getValue(),
                        getEnvironmentVariable(ENVIRONMENT),
                        clientId));
    }

    public Map<String, String> getSsmParameters(String path) {
        return getSsmParameters(path, false);
    }

    public Map<String, String> getSsmParameters(String path, boolean recursive) {
        if (recursive) {
            return ssmProvider.recursive().getMultiple(path);
        } else {
            return ssmProvider.getMultiple(path);
        }
    }

    public boolean isRunningLocally() {
        return Boolean.parseBoolean(getEnvironmentVariable(IS_LOCAL));
    }

    public long getBearerAccessTokenTtl() {
        return Optional.ofNullable(getEnvironmentVariable(BEARER_TOKEN_TTL))
                .map(Long::valueOf)
                .orElse(DEFAULT_BEARER_TOKEN_TTL_IN_SECS);
    }

    public String getSigningKeyId() {
        return ssmProvider.get(getEnvironmentVariable(SIGNING_KEY_ID_PARAM));
    }

    public CredentialIssuerConfig getCredentialIssuerActiveConnectionConfig(
            String credentialIssuerId) {
        Map<String, String> result =
                getSsmParameters(
                        String.format(
                                "%s/%s/connections/%s",
                                getEnvironmentVariable(CREDENTIAL_ISSUERS_CONFIG_PARAM_PREFIX),
                                credentialIssuerId,
                                getActiveConnection(credentialIssuerId)));

        CredentialIssuerConfig credentialIssuerConfig =
                new ObjectMapper().convertValue(result, CredentialIssuerConfig.class);
        credentialIssuerConfig.setId(credentialIssuerId);

        return credentialIssuerConfig;
    }

    public List<String> getClientRedirectUrls(String clientId) {
        String redirectUrlStrings =
                ssmProvider.get(
                        String.format(
                                "/%s/core/clients/%s/validRedirectUrls",
                                getEnvironmentVariable(ENVIRONMENT), clientId));

        return Arrays.asList(redirectUrlStrings.split(CLIENT_REDIRECT_URL_SEPARATOR));
    }

    public String getCriPrivateApiKey(String criId) {
        String secretId =
                String.format(
                        "%s/credential-issuers/%s/api-key",
                        getEnvironmentVariable(ENVIRONMENT), criId);
        try {
            String secretValue = getSecretValue(secretId);

            if (secretValue != null) {
                Map<String, String> secret =
                        objectMapper.readValue(secretValue, new TypeReference<>() {});
                return secret.get(API_KEY);
            }
            return null;
        } catch (JsonProcessingException e) {
            LOGGER.error(
                    "Failed to parse the api key secret from secrets manager for client: {}",
                    criId);
            return null;
        }
    }

    public String getActiveConnection(String credentialIssuerId) {
        return getSsmParameter(
                String.format(
                        "%s/%s/activeConnection",
                        getEnvironmentVariable(CREDENTIAL_ISSUERS_CONFIG_PARAM_PREFIX),
                        credentialIssuerId));
    }

    public boolean isUnavailable(String credentialIssuerId) {
        String unavailable =
                getSsmParameter(
                        String.format(
                                "%s/%s/unavailable",
                                getEnvironmentVariable(CREDENTIAL_ISSUERS_CONFIG_PARAM_PREFIX),
                                credentialIssuerId));

        return Boolean.parseBoolean(unavailable);
    }

    public String getAllowedSharedAttributes(String credentialIssuerId) {
        return getSsmParameter(
                String.format(
                        "%s/%s/allowedSharedAttributes",
                        getEnvironmentVariable(CREDENTIAL_ISSUERS_CONFIG_PARAM_PREFIX),
                        credentialIssuerId));
    }

    public boolean isEnabled(String credentialIssuerId) {
        String enabled =
                getSsmParameter(
                        String.format(
                                "%s/%s/enabled",
                                getEnvironmentVariable(CREDENTIAL_ISSUERS_CONFIG_PARAM_PREFIX),
                                credentialIssuerId));

        return Boolean.parseBoolean(enabled);
    }

    public Map<String, ContraIndicatorScore> getContraIndicatorScoresMap() {
        String secretId =
                String.format(
                        ConfigurationVariable.CI_SCORING_CONFIG.getValue(),
                        getEnvironmentVariable(ENVIRONMENT));
        try {
            String secretValue = getSecretValue(secretId);
            List<ContraIndicatorScore> scoresList =
                    objectMapper.readValue(secretValue, new TypeReference<>() {});
            Map<String, ContraIndicatorScore> scoresMap = new HashMap<>();
            for (ContraIndicatorScore scores : scoresList) {
                String ci = scores.getCi();
                scoresMap.put(ci, scores);
            }
            return scoresMap;
        } catch (JsonProcessingException e) {
            LOGGER.error("Failed to parse contra-indicator scoring config");
            return Collections.emptyMap();
        }
    }

    private String getSecretValue(String secretId) {
        try {
            return secretsProvider.get(secretId);
        } catch (DecryptionFailureException e) {
            LOGGER.error(
                    "Secrets manager failed to decrypt the protected secret using the configured KMS key because: {}",
                    e.getMessage());
        } catch (InternalServiceErrorException e) {
            LOGGER.error("Internal server error occurred with Secrets manager: {}", e.getMessage());
        } catch (InvalidParameterException e) {
            LOGGER.error(
                    "An invalid value was provided for the param value: {}, details: {}",
                    secretId,
                    e.getMessage());
        } catch (InvalidRequestException e) {
            LOGGER.error(
                    "Parameter value is not valid for the current state of the resource, details: {}",
                    e.getMessage());
        } catch (ResourceNotFoundException e) {
            LOGGER.warn(
                    "Failed to find the resource within Secrets manager: {}, details: {}",
                    secretId,
                    e.getMessage());
        }
        return null;
    }
}
