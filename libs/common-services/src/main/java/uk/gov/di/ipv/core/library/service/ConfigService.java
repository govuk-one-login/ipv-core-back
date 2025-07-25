package uk.gov.di.ipv.core.library.service;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.ObjectMapper;
import lombok.Getter;
import lombok.Setter;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
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
import uk.gov.di.ipv.core.library.exceptions.ConfigParameterNotFoundException;
import uk.gov.di.ipv.core.library.exceptions.ConfigParseException;
import uk.gov.di.ipv.core.library.exceptions.NoConfigForConnectionException;
import uk.gov.di.ipv.core.library.helpers.LogHelper;
import uk.gov.di.ipv.core.library.persistence.item.CriOAuthSessionItem;

import java.util.Arrays;
import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import java.util.stream.Collectors;

public abstract class ConfigService {
    private static final ObjectMapper OBJECT_MAPPER = new ObjectMapper();
    private static final Logger LOGGER = LogManager.getLogger();
    private static final String APP_CONFIG_SOURCE = "app-config";

    @Getter @Setter private static boolean local = false;

    @ExcludeFromGeneratedCoverageReport
    public static ConfigService create() {
        if (isLocal()) {
            return new YamlConfigService();
        }
        if (Objects.equals(
                System.getenv(EnvironmentVariable.CONFIG_SOURCE.name()), APP_CONFIG_SOURCE)) {
            return new AppConfigService();
        }
        return new SsmConfigService();
    }

    public abstract List<String> getFeatureSet();

    public abstract void setFeatureSet(List<String> featureSet);

    protected abstract String getParameter(String path);

    protected abstract Map<String, String> getParametersByPrefix(String path);

    protected abstract String getSecret(String path);

    public String getEnvironmentVariable(EnvironmentVariable environmentVariable) {
        return System.getenv(environmentVariable.name());
    }

    public Integer getIntegerEnvironmentVariable(EnvironmentVariable environmentVariable) {
        return getIntegerEnvironmentVariable(environmentVariable, null);
    }

    public Integer getIntegerEnvironmentVariable(
            EnvironmentVariable environmentVariable, Integer defaultValue) {
        var value = System.getenv(environmentVariable.name());
        if (value == null) {
            return defaultValue;
        }
        return Integer.valueOf(value);
    }

    public String getParameter(
            ConfigurationVariable configurationVariable, String... pathProperties) {
        return getParameter(formatPath(configurationVariable.getPath(), pathProperties));
    }

    public boolean getBooleanParameter(
            ConfigurationVariable configurationVariable, String... pathProperties) {
        return Boolean.parseBoolean(getParameter(configurationVariable, pathProperties));
    }

    public long getLongParameter(
            ConfigurationVariable configurationVariable, String... pathProperties) {
        return Long.parseLong(getParameter(configurationVariable, pathProperties));
    }

    public List<String> getHistoricSigningKeys(String criId) {
        return Arrays.asList(
                getParameter(ConfigurationVariable.CREDENTIAL_ISSUER_HISTORIC_SIGNING_KEYS, criId)
                        .split("/"));
    }

    public List<String> getStringListParameter(
            ConfigurationVariable configurationVariable, String... pathProperties) {
        return Arrays.asList(getParameter(configurationVariable, pathProperties).split(","));
    }

    public String getSecret(ConfigurationVariable secretVariable, String... pathProperties) {
        return getSecret(formatPath(secretVariable.getPath(), pathProperties));
    }

    private String formatPath(String path, String... pathProperties) {
        return String.format(path, (Object[]) pathProperties);
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
        var prefix =
                String.format(
                        ConfigurationVariable.CREDENTIAL_ISSUER_CONFIG.getPath(),
                        criId,
                        connection);
        var parameters = getParametersByPrefix(prefix);
        if (parameters.size() > 1) {
            parameters =
                    parameters.entrySet().stream()
                            .map(
                                    entry -> {
                                        var key = entry.getKey().substring(prefix.length() + 1);
                                        var value = entry.getValue();
                                        if (key.equals("signingKey")
                                                || key.equals("encryptionKey")) {
                                            value = value.replace("\\", "");
                                        }
                                        return Map.entry(key, value);
                                    })
                            .collect(Collectors.toMap(Map.Entry::getKey, Map.Entry::getValue));

            return OBJECT_MAPPER.convertValue(parameters, configType);
        }

        try {
            String parameter =
                    getParameter(ConfigurationVariable.CREDENTIAL_ISSUER_CONFIG, criId, connection);
            return OBJECT_MAPPER.readValue(parameter, configType);
        } catch (ConfigParameterNotFoundException e) {
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
        var prefix = ConfigurationVariable.CIMIT_CONFIG.getPath();
        var config = getParametersByPrefix(prefix);
        if (config.size() > 1) {
            return config.entrySet().stream()
                    .map(
                            entry -> {
                                var key = entry.getKey().substring(prefix.length() + 1);
                                try {
                                    var value =
                                            OBJECT_MAPPER.readValue(
                                                    entry.getValue(),
                                                    new TypeReference<List<MitigationRoute>>() {});
                                    return Map.entry(key, value);
                                } catch (JsonProcessingException e) {
                                    throw new RuntimeException(
                                            "Failed to parse routes for key: " + entry.getKey(), e);
                                }
                            })
                    .collect(Collectors.toMap(Map.Entry::getKey, Map.Entry::getValue));
        }

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
        } catch (ConfigParameterNotFoundException ex) {
            LOGGER.warn(
                    LogHelper.buildLogMessage(
                            "SSM parameter not found for feature flag: " + featureFlagValue));
            return false;
        }
    }

    public Map<String, Cri> getIssuerCris() {
        var prefix = "credentialIssuers";
        var allCriParameters =
                getParametersByPrefix("credentialIssuers").entrySet().stream()
                        .collect(
                                Collectors.toMap(
                                        e -> e.getKey().substring(prefix.length()),
                                        Map.Entry::getValue));

        var issuerToCriMap = new HashMap<String, Cri>();

        for (Map.Entry<String, String> entry : allCriParameters.entrySet()) {
            var fullPath = entry.getKey();
            var value = entry.getValue();

            var cri = findCriFromPath(fullPath);
            if (cri == null) {
                continue;
            }

            var criConfig = createCriConfigFromParameters(allCriParameters, cri, fullPath);
            if (criConfig != null) {
                var issuer = criConfig.getComponentId();
                issuerToCriMap.put(issuer, cri);
            } else {
                try {
                    criConfig = OBJECT_MAPPER.readValue(value, CriConfig.class);
                    var issuer = criConfig.getComponentId();
                    issuerToCriMap.put(issuer, cri);
                } catch (JsonProcessingException e) {
                    throw new ConfigParseException(
                            String.format(
                                    "Failed to parse credential issuer configuration at path '%s': %s",
                                    fullPath, e));
                }
            }
        }

        return issuerToCriMap;
    }

    private CriConfig createCriConfigFromParameters(
            Map<String, String> allCriParameters, Cri cri, String fullPath) {
        var regex = String.format("/%s/connections/([^/]+)/[^/]+", cri.getId());
        var pattern = Pattern.compile(regex);
        var matcher = pattern.matcher(fullPath);

        var data =
                allCriParameters.entrySet().stream()
                        .filter(e -> pattern.matcher(e.getKey()).matches())
                        .collect(Collectors.toMap(Map.Entry::getKey, Map.Entry::getValue));

        if (matcher.find()) {
            var key = String.format("/%s/connections/%s", cri.getId(), matcher.group(1));
            return CriConfig.builder()
                    .componentId(data.get(String.format("%s/componentId", key)))
                    .signingKey(data.get(String.format("%s/signingKey", key)))
                    .build();
        }
        return null;
    }

    private Cri findCriFromPath(String parameterPath) {
        Pattern pattern = Pattern.compile("([^/]+)/connections");
        Matcher matcher = pattern.matcher(parameterPath);

        if (matcher.find()) {
            return Cri.fromId(matcher.group(1));
        }
        return null;
    }
}
