package uk.gov.di.ipv.core.library.service;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.apache.logging.log4j.message.StringMapMessage;
import software.amazon.awssdk.http.urlconnection.UrlConnectionHttpClient;
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
import uk.gov.di.ipv.core.library.annotations.ExcludeFromGeneratedCoverageReport;
import uk.gov.di.ipv.core.library.config.ConfigurationVariable;
import uk.gov.di.ipv.core.library.config.EnvironmentVariable;
import uk.gov.di.ipv.core.library.config.FeatureFlag;
import uk.gov.di.ipv.core.library.domain.ContraIndicatorConfig;
import uk.gov.di.ipv.core.library.domain.Cri;
import uk.gov.di.ipv.core.library.domain.MitigationRoute;
import uk.gov.di.ipv.core.library.dto.CriConfig;
import uk.gov.di.ipv.core.library.dto.OauthCriConfig;
import uk.gov.di.ipv.core.library.dto.RestCriConfig;
import uk.gov.di.ipv.core.library.exceptions.ConfigException;
import uk.gov.di.ipv.core.library.exceptions.ConfigParseException;
import uk.gov.di.ipv.core.library.exceptions.NoConfigForConnectionException;
import uk.gov.di.ipv.core.library.exceptions.NoCriForIssuerException;
import uk.gov.di.ipv.core.library.helpers.LogHelper;
import uk.gov.di.ipv.core.library.persistence.item.CriOAuthSessionItem;

import java.nio.file.Path;
import java.util.ArrayList;
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
import static uk.gov.di.ipv.core.library.config.EnvironmentVariable.SIGNING_KEY_ID_PARAM;
import static uk.gov.di.ipv.core.library.helpers.LogHelper.LogField.LOG_CONNECTION;
import static uk.gov.di.ipv.core.library.helpers.LogHelper.LogField.LOG_CRI_ID;
import static uk.gov.di.ipv.core.library.helpers.LogHelper.LogField.LOG_FEATURE_SET;
import static uk.gov.di.ipv.core.library.helpers.LogHelper.LogField.LOG_MESSAGE_DESCRIPTION;
import static uk.gov.di.ipv.core.library.helpers.LogHelper.LogField.LOG_PARAMETER_PATH;
import static uk.gov.di.ipv.core.library.helpers.LogHelper.LogField.LOG_SECRET_ID;

public class ConfigService {

    private static final ObjectMapper OBJECT_MAPPER = new ObjectMapper();
    private static final long DEFAULT_BEARER_TOKEN_TTL_IN_SECS = 3600L;
    private static final int DEFAULT_CACHE_DURATION_MINUTES = 3;
    private static final String CLIENT_REDIRECT_URL_SEPARATOR = ",";
    private static final String API_KEY = "apiKey";
    private static final String CORE_BASE_PATH = "/%s/core/";
    private static final Logger LOGGER = LogManager.getLogger();
    private final SSMProvider ssmProvider;
    private final SecretsProvider secretsProvider;

    private List<String> featureSet;

    public ConfigService(
            SSMProvider ssmProvider, SecretsProvider secretsProvider, List<String> featureSet) {
        this.ssmProvider = ssmProvider;
        this.secretsProvider = secretsProvider;
        setFeatureSet(featureSet);
    }

    public ConfigService(SSMProvider ssmProvider, SecretsProvider secretsProvider) {
        this(ssmProvider, secretsProvider, null);
    }

    @ExcludeFromGeneratedCoverageReport
    public ConfigService() {
        var cacheDuration =
                getEnvironmentVariable(CONFIG_SERVICE_CACHE_DURATION_MINUTES) == null
                        ? DEFAULT_CACHE_DURATION_MINUTES
                        : Integer.parseInt(
                                getEnvironmentVariable(CONFIG_SERVICE_CACHE_DURATION_MINUTES));

        this.ssmProvider =
                ParamManager.getSsmProvider(
                                SsmClient.builder()
                                        .httpClient(UrlConnectionHttpClient.create())
                                        .build())
                        .defaultMaxAge(cacheDuration, MINUTES);

        this.secretsProvider =
                ParamManager.getSecretsProvider(
                                SecretsManagerClient.builder()
                                        .httpClient(UrlConnectionHttpClient.create())
                                        .build())
                        .defaultMaxAge(cacheDuration, MINUTES);
    }

    public boolean isLocalDev() {
        return "true".equals(getEnvironmentVariable(EnvironmentVariable.LOCAL_DEV));
    }

    public List<String> getFeatureSet() {
        return featureSet;
    }

    public void setFeatureSet(List<String> featureSet) {
        this.featureSet = featureSet;
    }

    public String getEnvironmentVariable(EnvironmentVariable environmentVariable) {
        return System.getenv(environmentVariable.name());
    }

    public String getSsmParameter(
            ConfigurationVariable configurationVariable, String... pathProperties) {
        return getSsmParameterWithOverride(configurationVariable.getPath(), pathProperties);
    }

    private String getSsmParameterWithOverride(String templatePath, String... pathProperties) {
        if (this.featureSet != null) {
            for (String fs : this.featureSet) {
                final Path featureSetPath =
                        Path.of(resolveFeatureSetPath(fs, templatePath, pathProperties));
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
                                    .with(LOG_FEATURE_SET.getFieldName(), fs));
                }
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

    private String resolveFeatureSetPath(String featureSet, String path, String... pathProperties) {
        return resolveBasePath()
                + String.format("features/%s/", featureSet)
                + String.format(path, (Object[]) pathProperties);
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

    public String getCriPrivateApiKeyForActiveConnection(Cri cri) {
        return getApiKeyFromSecretManager(cri, getActiveConnection(cri));
    }

    public String getAppApiKey(String appId) {
        return getApiKeyFromSecretManager(appId);
    }

    public String getCriPrivateApiKey(CriOAuthSessionItem criOAuthSessionItem) {
        return getApiKeyFromSecretManager(
                Cri.fromId(criOAuthSessionItem.getCriId()), criOAuthSessionItem.getConnection());
    }

    public String getCriOAuthClientSecret(CriOAuthSessionItem criOAuthSessionItem) {
        return getOAuthClientSecretFromSecretManager(
                Cri.fromId(criOAuthSessionItem.getCriId()), criOAuthSessionItem.getConnection());
    }

    public OauthCriConfig getOauthCriActiveConnectionConfig(Cri cri) {
        return getOauthCriConfigForConnection(getActiveConnection(cri), cri);
    }

    public OauthCriConfig getOauthCriConfig(CriOAuthSessionItem criOAuthSessionItem) {
        return getOauthCriConfigForConnection(
                criOAuthSessionItem.getConnection(), Cri.fromId(criOAuthSessionItem.getCriId()));
    }

    public OauthCriConfig getOauthCriConfigForConnection(String connection, Cri cri) {
        return getCriConfigForType(connection, cri, OauthCriConfig.class);
    }

    public RestCriConfig getRestCriConfig(Cri cri) {
        return getCriConfigForType(getActiveConnection(cri), cri, RestCriConfig.class);
    }

    public CriConfig getCriConfig(Cri cri) {
        return getCriConfigForType(getActiveConnection(cri), cri, CriConfig.class);
    }

    public String getActiveConnection(Cri cri) {
        final String pathTemplate =
                ConfigurationVariable.CREDENTIAL_ISSUERS.getPath() + "/%s/activeConnection";
        return getSsmParameterWithOverride(pathTemplate, cri.getId());
    }

    public String getComponentId(Cri cri) {
        var criConfig = getOauthCriActiveConnectionConfig(cri);
        return criConfig.getComponentId();
    }

    public String getAllowedSharedAttributes(Cri cri) {
        final String pathTemplate =
                ConfigurationVariable.CREDENTIAL_ISSUERS.getPath() + "/%s/allowedSharedAttributes";
        return getSsmParameterWithOverride(pathTemplate, cri.getId());
    }

    public boolean isEnabled(String credentialIssuerId) {
        final String pathTemplate =
                ConfigurationVariable.CREDENTIAL_ISSUERS.getPath() + "/%s/enabled";
        return Boolean.parseBoolean(getSsmParameterWithOverride(pathTemplate, credentialIssuerId));
    }

    public Map<String, ContraIndicatorConfig> getContraIndicatorConfigMap() {
        try {
            String secretValue = getCoreSecretValue(ConfigurationVariable.CI_CONFIG);
            List<ContraIndicatorConfig> configList =
                    OBJECT_MAPPER.readValue(secretValue, new TypeReference<>() {});
            Map<String, ContraIndicatorConfig> configMap = new HashMap<>();
            for (ContraIndicatorConfig config : configList) {
                configMap.put(config.getCi(), config);
            }
            return configMap;
        } catch (JsonProcessingException e) {
            LOGGER.error(LogHelper.buildLogMessage("Failed to parse contra-indicator config"));
            return Collections.emptyMap();
        }
    }

    public Map<String, List<MitigationRoute>> getCimitConfig() throws ConfigException {
        final String cimitConfig = getSsmParameter(ConfigurationVariable.CIMIT_CONFIG);
        try {
            return OBJECT_MAPPER.readValue(
                    cimitConfig, new TypeReference<HashMap<String, List<MitigationRoute>>>() {});
        } catch (JsonProcessingException e) {
            throw new ConfigException("Failed to parse CIMit configuration");
        }
    }

    public boolean enabled(FeatureFlag featureFlag) {
        return enabled(featureFlag.getName());
    }

    public boolean enabled(String featureFlagValue) {
        try {
            return Boolean.parseBoolean(
                    getSsmParameter(ConfigurationVariable.FEATURE_FLAGS, featureFlagValue));
        } catch (ParameterNotFoundException ex) {
            LOGGER.warn(
                    (new StringMapMessage())
                            .with(
                                    LOG_MESSAGE_DESCRIPTION.getFieldName(),
                                    "SSM parameter not found for feature flag:"
                                            + featureFlagValue));
            return false;
        }
    }

    public String getCoreSecretValue(ConfigurationVariable secretName) {
        String secretId = resolveBasePath() + secretName.getPath();
        return getSecretValue(secretId);
    }

    private String getSecretValue(String secretId) {
        try {
            return secretsProvider.get(secretId);
        } catch (DecryptionFailureException e) {
            LOGGER.error(
                    LogHelper.buildErrorMessage(
                            "Secrets manager failed to decrypt the protected secret using the configured KMS key",
                            e));
        } catch (InternalServiceErrorException e) {
            LOGGER.error(
                    LogHelper.buildErrorMessage(
                            "Internal server error occurred with Secrets manager", e));
        } catch (InvalidParameterException e) {
            LOGGER.error(
                    LogHelper.buildErrorMessage(
                            String.format(
                                    "An invalid value was provided for the param value: %s",
                                    secretId),
                            e));
        } catch (InvalidRequestException e) {
            LOGGER.error(
                    LogHelper.buildErrorMessage(
                            "Parameter value is not valid for the current state of the resource",
                            e));
        } catch (ResourceNotFoundException e) {
            LOGGER.error(
                    LogHelper.buildErrorMessage(
                                    "Failed to find the resource within Secrets manager.", e)
                            .with(LOG_SECRET_ID.getFieldName(), secretId));
        }
        return null;
    }

    private String getApiKeyFromSecretManager(Cri cri, String connection) {
        String criId = cri.getId();
        String secretId =
                String.format(
                        "/%s/credential-issuers/%s/connections/%s/api-key",
                        getEnvironmentVariable(ENVIRONMENT), criId, connection);
        return getSecretValue(criId, connection, secretId);
    }

    private String getApiKeyFromSecretManager(String appId) {
        String secretId = resolvePath("%s/api-key", appId);
        return getSecretValue(appId, null, secretId);
    }

    private String getSecretValue(String criId, String connection, String secretId) {
        try {
            String secretValue = getSecretValue(secretId);

            if (secretValue != null) {
                Map<String, String> secret =
                        OBJECT_MAPPER.readValue(secretValue, new TypeReference<>() {});
                return secret.get(API_KEY);
            }
            LOGGER.warn(
                    (new StringMapMessage())
                            .with(LOG_MESSAGE_DESCRIPTION.getFieldName(), "API key not found")
                            .with(LOG_CRI_ID.getFieldName(), criId)
                            .with(LOG_CONNECTION.getFieldName(), connection));
            return null;
        } catch (JsonProcessingException e) {
            LOGGER.error(
                    "Failed to parse the api key secret from secrets manager for client: {}",
                    criId);
            return null;
        }
    }

    private String getOAuthClientSecretFromSecretManager(Cri cri, String connection) {
        String criId = cri.getId();
        String secretId =
                String.format(
                        "/%s/credential-issuers/%s/connections/%s/oauth-client-secret",
                        getEnvironmentVariable(ENVIRONMENT), criId, connection);

        String secretValue = getSecretValue(secretId);

        if (secretValue == null) {
            LOGGER.warn(
                    (new StringMapMessage())
                            .with(
                                    LOG_MESSAGE_DESCRIPTION.getFieldName(),
                                    "OAuth secret value not found")
                            .with(LOG_CRI_ID.getFieldName(), criId)
                            .with(LOG_CONNECTION.getFieldName(), connection));
        }

        return secretValue;
    }

    private <T> T getCriConfigForType(String connection, Cri cri, Class<T> configType) {
        String criId = cri.getId();
        final String pathTemplate =
                ConfigurationVariable.CREDENTIAL_ISSUERS.getPath() + "/%s/connections/%s";
        try {
            String parameter = ssmProvider.get(resolvePath(pathTemplate, criId, connection));
            return OBJECT_MAPPER.readValue(parameter, configType);
        } catch (ParameterNotFoundException e) {
            throw new NoConfigForConnectionException(
                    String.format(
                            "No config found for connection: '%s' and criId: '%s'",
                            connection, criId));
        } catch (JsonProcessingException e) {
            throw new ConfigParseException(
                    String.format(
                            "Failed to parse credential issuer configuration at parameter path '%s' because: '%s'",
                            pathTemplate, e));
        }
    }

    private List<String> getCriComponentIds(Cri cri) {
        final String pathTemplate =
                ConfigurationVariable.CREDENTIAL_ISSUERS.getPath() + "/%s/connections";
        var criId = cri.getId();
        var result = new ArrayList<String>();
        try {
            var parameters = ssmProvider.getMultiple(resolvePath(pathTemplate, criId));
            for (var parameter : parameters.values()) {
                var criConfig = OBJECT_MAPPER.readValue(parameter, CriConfig.class);

                result.add(criConfig.getComponentId());
            }
            return result;
        } catch (ParameterNotFoundException e) {
            throw new NoConfigForConnectionException(
                    String.format("No config found for criId: '%s'", criId));
        } catch (JsonProcessingException e) {
            throw new ConfigParseException(
                    String.format(
                            "Failed to parse credential issuer configuration at parameter path '%s' because: '%s'",
                            pathTemplate, e));
        }
    }

    public Cri getCriByIssuer(String issuer) throws NoCriForIssuerException {
        for (var cri : Cri.values()) {
            for (var componentId : getCriComponentIds(cri)) {
                if (issuer.equals(componentId)) {
                    return cri;
                }
            }
        }
        throw new NoCriForIssuerException(String.format("No cri found for issuer: '%s'", issuer));
    }
}
