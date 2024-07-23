package uk.gov.di.ipv.core.library.service;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.ObjectMapper;
import lombok.Getter;
import lombok.Setter;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import software.amazon.awssdk.services.ssm.model.ParameterNotFoundException;
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

import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;

import static uk.gov.di.ipv.core.library.config.EnvironmentVariable.BEARER_TOKEN_TTL;
import static uk.gov.di.ipv.core.library.helpers.LogHelper.LogField.LOG_PARAMETER_PATH;

public abstract class ConfigService {
    private static final ObjectMapper OBJECT_MAPPER = new ObjectMapper();
    private static final Logger LOGGER = LogManager.getLogger();
    private static final String API_KEY = "apiKey";
    private static final long DEFAULT_BEARER_TOKEN_TTL_IN_SECS = 3600L;

    @Getter @Setter private List<String> featureSet;

    protected abstract String getParameter(String path);

    protected abstract Map<String, String> getParametersByPrefix(String path);

    protected abstract String getSecret(String path);

    public String getEnvironmentVariable(EnvironmentVariable environmentVariable) {
        return System.getenv(environmentVariable.name());
    }

    public String getParameter(
            ConfigurationVariable configurationVariable, String... pathProperties) {
        return getParameter(formatPath(configurationVariable.getPath(), pathProperties));
    }

    public boolean getBooleanParameter(
            ConfigurationVariable configurationVariable, String... pathProperties) {
        return Boolean.parseBoolean(getParameter(configurationVariable, pathProperties));
    }

    public List<String> getStringListParameter(
            ConfigurationVariable configurationVariable, String... pathProperties) {
        return Arrays.asList(getParameter(configurationVariable, pathProperties).split(","));
    }

    public String getSecret(ConfigurationVariable secretVariable, String... pathProperties) {
        return getSecret(formatPath(secretVariable.getPath(), pathProperties));
    }

    public String getApiKeySecret(
            ConfigurationVariable configurationVariable, String... pathProperties) {
        try {
            var secretValue = getSecret(configurationVariable, pathProperties);

            if (secretValue != null) {
                Map<String, String> secret =
                        OBJECT_MAPPER.readValue(secretValue, new TypeReference<>() {});
                return secret.get(API_KEY);
            }
            LOGGER.warn(
                    LogHelper.buildLogMessage("API key not found")
                            .with(
                                    LOG_PARAMETER_PATH.getFieldName(),
                                    formatPath(configurationVariable.getPath(), pathProperties)));
            return null;
        } catch (JsonProcessingException e) {
            LOGGER.error(
                    LogHelper.buildLogMessage(
                                    "Failed to parse the api key secret from secrets manager")
                            .with(
                                    LOG_PARAMETER_PATH.getFieldName(),
                                    formatPath(configurationVariable.getPath(), pathProperties)));
            return null;
        }
    }

    private String formatPath(String path, String... pathProperties) {
        return String.format(path, (Object[]) pathProperties);
    }

    public boolean isLocalDev() {
        return "true".equals(getEnvironmentVariable(EnvironmentVariable.LOCAL_DEV));
    }

    // PYIC-7048 Replace this with proper config
    public long getBearerAccessTokenTtl() {
        return Optional.ofNullable(getEnvironmentVariable(BEARER_TOKEN_TTL))
                .map(Long::valueOf)
                .orElse(DEFAULT_BEARER_TOKEN_TTL_IN_SECS);
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

    public RestCriConfig getRestCriConfigForConnection(String connection, Cri cri) {
        return getCriConfigForType(connection, cri, RestCriConfig.class);
    }

    public CriConfig getCriConfig(Cri cri) {
        return getCriConfigForType(getActiveConnection(cri), cri, CriConfig.class);
    }

    private <T> T getCriConfigForType(String connection, Cri cri, Class<T> configType) {
        String criId = cri.getId();
        try {
            String parameter =
                    getParameter(ConfigurationVariable.CREDENTIAL_ISSUER_CONFIG, criId, connection);
            return OBJECT_MAPPER.readValue(parameter, configType);
        } catch (ParameterNotFoundException e) {
            throw new NoConfigForConnectionException(
                    String.format(
                            "No config found for connection: '%s' and criId: '%s'",
                            connection, criId));
        } catch (JsonProcessingException e) {
            throw new ConfigParseException(
                    String.format(
                            "Failed to parse credential issuer configuration '%s' because: '%s'",
                            criId, e));
        }
    }

    public String getActiveConnection(Cri cri) {
        return getParameter(ConfigurationVariable.CREDENTIAL_ISSUER_ACTIVE_CONNECTION, cri.getId());
    }

    public Map<String, ContraIndicatorConfig> getContraIndicatorConfigMap() {
        try {
            String secretValue = getSecret(ConfigurationVariable.CI_CONFIG);
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
        final String cimitConfig = getParameter(ConfigurationVariable.CIMIT_CONFIG);
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
            return getBooleanParameter(ConfigurationVariable.FEATURE_FLAGS, featureFlagValue);
        } catch (ParameterNotFoundException ex) {
            LOGGER.warn(
                    LogHelper.buildLogMessage(
                            "SSM parameter not found for feature flag: " + featureFlagValue));
            return false;
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

    private List<String> getCriComponentIds(Cri cri) {
        final String pathTemplate =
                ConfigurationVariable.CREDENTIAL_ISSUER_CONNECTION_PREFIX.getPath();
        var criId = cri.getId();
        var result = new ArrayList<String>();
        try {
            var parameters = getParametersByPrefix(formatPath(pathTemplate, criId));
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
}
