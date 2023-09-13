package uk.gov.di.ipv.core.library.service;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.apache.logging.log4j.message.StringMapMessage;
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
import uk.gov.di.ipv.core.library.config.FeatureFlag;
import uk.gov.di.ipv.core.library.domain.ContraIndicatorMitigation;
import uk.gov.di.ipv.core.library.domain.ContraIndicatorScore;
import uk.gov.di.ipv.core.library.dto.CredentialIssuerConfig;
import uk.gov.di.ipv.core.library.exceptions.ConfigException;
import uk.gov.di.ipv.core.library.exceptions.NoConfigForConnectionException;
import uk.gov.di.ipv.core.library.persistence.item.CriOAuthSessionItem;

import java.net.URI;
import java.nio.file.Path;
import java.util.Arrays;
import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;

import static java.time.temporal.ChronoUnit.MINUTES;
import static uk.gov.di.ipv.core.library.config.EnvironmentVariable.BEARER_TOKEN_TTL;
import static uk.gov.di.ipv.core.library.config.EnvironmentVariable.CONFIG_SERVICE_CACHE_DURATION_MINUTES;
import static uk.gov.di.ipv.core.library.config.EnvironmentVariable.ENVIRONMENT;
import static uk.gov.di.ipv.core.library.config.EnvironmentVariable.IS_LOCAL;
import static uk.gov.di.ipv.core.library.config.EnvironmentVariable.SIGNING_KEY_ID_PARAM;
import static uk.gov.di.ipv.core.library.helpers.LogHelper.LogField.LOG_ERROR_DESCRIPTION;
import static uk.gov.di.ipv.core.library.helpers.LogHelper.LogField.LOG_FEATURE_SET;
import static uk.gov.di.ipv.core.library.helpers.LogHelper.LogField.LOG_MESSAGE_DESCRIPTION;
import static uk.gov.di.ipv.core.library.helpers.LogHelper.LogField.LOG_PARAMETER_PATH;
import static uk.gov.di.ipv.core.library.helpers.LogHelper.LogField.LOG_SECRET_ID;

public class ConfigService {

    public static final int LOCALHOST_PORT = 4567;
    private static final String LOCALHOST_URI = "http://localhost:" + LOCALHOST_PORT;
    private static final long DEFAULT_BEARER_TOKEN_TTL_IN_SECS = 3600L;
    private static final String CLIENT_REDIRECT_URL_SEPARATOR = ",";
    private static final String API_KEY = "apiKey";
    private static final String CORE_BASE_PATH = "/%s/core/";
    private static final Logger LOGGER = LogManager.getLogger();
    private final SSMProvider ssmProvider;
    private final SecretsProvider secretsProvider;
    private final ObjectMapper objectMapper = new ObjectMapper();

    private String featureSet;

    public ConfigService(
            SSMProvider ssmProvider, SecretsProvider secretsProvider, String featureSet) {
        this.ssmProvider = ssmProvider;
        this.secretsProvider = secretsProvider;
        setFeatureSet(featureSet);
    }

    public ConfigService(SSMProvider ssmProvider, SecretsProvider secretsProvider) {
        this(ssmProvider, secretsProvider, null);
    }

    public ConfigService(String featureSet) {
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
                            .defaultMaxAge(
                                    Integer.parseInt(
                                            getEnvironmentVariable(
                                                    CONFIG_SERVICE_CACHE_DURATION_MINUTES)),
                                    MINUTES);

            this.secretsProvider =
                    ParamManager.getSecretsProvider(
                                    SecretsManagerClient.builder()
                                            .httpClient(UrlConnectionHttpClient.create())
                                            .build())
                            .defaultMaxAge(
                                    Integer.parseInt(
                                            getEnvironmentVariable(
                                                    CONFIG_SERVICE_CACHE_DURATION_MINUTES)),
                                    MINUTES);
        }
        setFeatureSet(featureSet);
    }

    public ConfigService() {
        this(null);
    }

    public SSMProvider getSsmProvider() {
        return ssmProvider;
    }

    public String getFeatureSet() {
        return featureSet;
    }

    public void setFeatureSet(String featureSet) {
        if (featureSet == null || featureSet.isBlank()) {
            this.featureSet = null;
        } else {
            this.featureSet = featureSet;
        }
    }

    public String getEnvironmentVariable(EnvironmentVariable environmentVariable) {
        return System.getenv(environmentVariable.name());
    }

    public String getSsmParameter(String path) {
        return ssmProvider.get(path);
    }

    public String getSsmParameter(
            ConfigurationVariable configurationVariable, String... pathProperties) {
        return getSsmParameterWithOverride(configurationVariable.getPath(), pathProperties);
    }

    private String getSsmParameterWithOverride(String templatePath, String... pathProperties) {
        if (getFeatureSet() != null) {
            final Path featureSetPath =
                    Path.of(resolveFeatureSetPath(templatePath, pathProperties));
            final String terminal = featureSetPath.getFileName().toString();
            final String basePath = featureSetPath.getParent().toString();
            final Map<String, String> overrides = ssmProvider.getMultiple(basePath);
            if (overrides.containsKey(terminal)) {
                return overrides.get(terminal);
            } else {
                LOGGER.debug(
                        (new StringMapMessage())
                                .with(
                                        LOG_MESSAGE_DESCRIPTION.getFieldName(),
                                        "Parameter not present for featureSet")
                                .with(LOG_PARAMETER_PATH.getFieldName(), templatePath)
                                .with(LOG_FEATURE_SET.getFieldName(), getFeatureSet()));
            }
        }
        return ssmProvider.get(resolvePath(templatePath, pathProperties));
    }

    private String resolveBasePath() {
        return String.format(CORE_BASE_PATH, getEnvironmentVariable(ENVIRONMENT));
    }

    protected String resolvePath(String path, String... pathProperties) {
        return resolveBasePath() + String.format(path, (Object[]) pathProperties);
    }

    private String resolveFeatureSetPath(String path, String... pathProperties) {
        return resolveBasePath()
                + String.format("features/%s/", getFeatureSet())
                + String.format(path, (Object[]) pathProperties);
    }

    public Map<String, String> getSsmParameters(
            String path, boolean recursive, String... pathProperties) {
        var provider = recursive ? ssmProvider.recursive() : ssmProvider;
        Map<String, String> parameters =
                new HashMap<>(provider.getMultiple(resolvePath(path, pathProperties)));
        if (getFeatureSet() != null) {
            parameters.putAll(provider.getMultiple(resolveFeatureSetPath(path, pathProperties)));
        }
        return parameters;
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

    public List<String> getClientRedirectUrls(String clientId) {
        String redirectUrlStrings =
                getSsmParameter(ConfigurationVariable.CLIENT_VALID_REDIRECT_URLS, clientId);
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

    public CredentialIssuerConfig getCredentialIssuerActiveConnectionConfig(
            String credentialIssuerId) {
        return getCriConfigForConnection(
                getActiveConnection(credentialIssuerId), credentialIssuerId);
    }

    public CredentialIssuerConfig getCriConfig(CriOAuthSessionItem criOAuthSessionItem) {
        return getCriConfigForConnection(
                criOAuthSessionItem.getConnection(), criOAuthSessionItem.getCriId());
    }

    public CredentialIssuerConfig getCriConfigForConnection(String connection, String criId) {
        final String pathTemplate =
                ConfigurationVariable.CREDENTIAL_ISSUERS.getPath() + "/%s/connections/%s";
        Map<String, String> result = getSsmParameters(pathTemplate, false, criId, connection);

        if (result.isEmpty()) {
            throw new NoConfigForConnectionException(
                    String.format(
                            "No config found for connection: '%s' and criId: '%s'",
                            connection, criId));
        }

        return objectMapper.convertValue(result, CredentialIssuerConfig.class);
    }

    public String getActiveConnection(String credentialIssuerId) {
        final String pathTemplate =
                ConfigurationVariable.CREDENTIAL_ISSUERS.getPath() + "/%s/activeConnection";
        return getSsmParameterWithOverride(pathTemplate, credentialIssuerId);
    }

    public String getComponentId(String credentialIssuerId) {
        String activeConnection = getActiveConnection(credentialIssuerId);
        final String pathTemplate =
                ConfigurationVariable.CREDENTIAL_ISSUERS.getPath()
                        + "/%s/connections/%s/componentId";
        return getSsmParameterWithOverride(pathTemplate, credentialIssuerId, activeConnection);
    }

    public boolean isUnavailable(String credentialIssuerId) {
        final String pathTemplate =
                ConfigurationVariable.CREDENTIAL_ISSUERS.getPath() + "/%s/unavailable";
        return Boolean.parseBoolean(getSsmParameterWithOverride(pathTemplate, credentialIssuerId));
    }

    public String getAllowedSharedAttributes(String credentialIssuerId) {
        final String pathTemplate =
                ConfigurationVariable.CREDENTIAL_ISSUERS.getPath() + "/%s/allowedSharedAttributes";
        return getSsmParameterWithOverride(pathTemplate, credentialIssuerId);
    }

    public boolean isEnabled(String credentialIssuerId) {
        final String pathTemplate =
                ConfigurationVariable.CREDENTIAL_ISSUERS.getPath() + "/%s/enabled";
        return Boolean.parseBoolean(getSsmParameterWithOverride(pathTemplate, credentialIssuerId));
    }

    public Map<String, ContraIndicatorScore> getContraIndicatorScoresMap() {
        String secretId = resolveBasePath() + ConfigurationVariable.CI_SCORING_CONFIG.getPath();
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

    public Map<String, ContraIndicatorMitigation> getCiMitConfig() throws ConfigException {
        final String ciMitConfig = getSsmParameter(ConfigurationVariable.CIMIT_CONFIG);
        try {
            return objectMapper.readValue(
                    ciMitConfig,
                    new TypeReference<HashMap<String, ContraIndicatorMitigation>>() {});
        } catch (JsonProcessingException e) {
            throw new ConfigException("Failed to parse CIMIT configuration");
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
            LOGGER.error(
                    new StringMapMessage()
                            .with(
                                    LOG_MESSAGE_DESCRIPTION.getFieldName(),
                                    "Failed to find the resource within Secrets manager.")
                            .with(LOG_SECRET_ID.getFieldName(), secretId)
                            .with(LOG_ERROR_DESCRIPTION.getFieldName(), e.getMessage()));
        }
        return null;
    }

    public boolean enabled(FeatureFlag featureFlag) {
        return Boolean.parseBoolean(
                getSsmParameter(ConfigurationVariable.FEATURE_FLAGS, featureFlag.getName()));
    }

    public boolean enabled(String featureFlagValue) {
        return Boolean.parseBoolean(
                getSsmParameter(ConfigurationVariable.FEATURE_FLAGS, featureFlagValue));
    }
}
