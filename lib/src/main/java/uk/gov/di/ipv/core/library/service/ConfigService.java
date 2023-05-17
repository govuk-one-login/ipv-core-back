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
import software.amazon.awssdk.services.ssm.model.ParameterNotFoundException;
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
                            .defaultMaxAge(3, MINUTES);

            this.secretsProvider =
                    ParamManager.getSecretsProvider(
                                    SecretsManagerClient.builder()
                                            .httpClient(UrlConnectionHttpClient.create())
                                            .build())
                            .defaultMaxAge(3, MINUTES);
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
        this.featureSet = featureSet;
    }

    public String getEnvironmentVariable(EnvironmentVariable environmentVariable) {
        return System.getenv(environmentVariable.name());
    }

    public String getSsmParameter(String path) {
        return ssmProvider.get(path);
    }

    public String getSsmParameter(
            ConfigurationVariable configurationVariable, String... pathProperties) {
        if (getFeatureSet() != null) {
            var featureSetPath =
                    resolveFeatureSetPath(configurationVariable.getPath(), pathProperties);
            try {
                return ssmProvider.get(featureSetPath);
            } catch (ParameterNotFoundException ignored) {
                LOGGER.debug(
                        (new StringMapMessage())
                                .with(
                                        LOG_MESSAGE_DESCRIPTION.getFieldName(),
                                        "Parameter not present for featureSet")
                                .with(
                                        LOG_PARAMETER_PATH.getFieldName(),
                                        configurationVariable.getPath())
                                .with(LOG_FEATURE_SET.getFieldName(), getFeatureSet()));
            }
        }
        return ssmProvider.get(resolvePath(configurationVariable.getPath(), pathProperties));
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

    public List<String> getClientRedirectUrls(String clientId) {
        String redirectUrlStrings =
                ssmProvider.get(resolvePath("clients/%s/validRedirectUrls", clientId));

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
        String activeConnection = getActiveConnection(credentialIssuerId);
        final String pathTemplate =
                ConfigurationVariable.CREDENTIAL_ISSUERS.getPath() + "/%s/connections/%s";
        Map<String, String> result =
                getSsmParameters(resolvePath(pathTemplate, credentialIssuerId, activeConnection));

        return new ObjectMapper().convertValue(result, CredentialIssuerConfig.class);
    }

    public String getActiveConnection(String credentialIssuerId) {
        final String pathTemplate =
                ConfigurationVariable.CREDENTIAL_ISSUERS.getPath() + "/%s/activeConnection";
        return getSsmParameter(resolvePath(pathTemplate, credentialIssuerId));
    }

    public String getComponentId(String credentialIssuerId) {
        String activeConnection = getActiveConnection(credentialIssuerId);
        final String pathTemplate =
                ConfigurationVariable.CREDENTIAL_ISSUERS.getPath()
                        + "/%s/connections/%s/componentId";
        return getSsmParameter(resolvePath(pathTemplate, credentialIssuerId, activeConnection));
    }

    public boolean isUnavailable(String credentialIssuerId) {
        final String pathTemplate =
                ConfigurationVariable.CREDENTIAL_ISSUERS.getPath() + "/%s/unavailable";
        return Boolean.parseBoolean(getSsmParameter(resolvePath(pathTemplate, credentialIssuerId)));
    }

    public String getAllowedSharedAttributes(String credentialIssuerId) {
        final String pathTemplate =
                ConfigurationVariable.CREDENTIAL_ISSUERS.getPath() + "/%s/allowedSharedAttributes";
        return getSsmParameter(resolvePath(pathTemplate, credentialIssuerId));
    }

    public boolean isEnabled(String credentialIssuerId) {
        final String pathTemplate =
                ConfigurationVariable.CREDENTIAL_ISSUERS.getPath() + "/%s/enabled";
        return Boolean.parseBoolean(getSsmParameter(resolvePath(pathTemplate, credentialIssuerId)));
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
}
