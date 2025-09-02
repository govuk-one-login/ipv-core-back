package uk.gov.di.ipv.core.library.service;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.dataformat.yaml.YAMLFactory;
import lombok.Getter;
import lombok.Setter;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import uk.gov.di.ipv.core.library.annotations.ExcludeFromGeneratedCoverageReport;
import uk.gov.di.ipv.core.library.config.ConfigurationVariable;
import uk.gov.di.ipv.core.library.config.EnvironmentVariable;
import uk.gov.di.ipv.core.library.config.FeatureFlag;
import uk.gov.di.ipv.core.library.config.domain.Config;
import uk.gov.di.ipv.core.library.domain.ContraIndicatorConfig;
import uk.gov.di.ipv.core.library.domain.Cri;
import uk.gov.di.ipv.core.library.domain.MitigationRoute;
import uk.gov.di.ipv.core.library.dto.CriConfig;
import uk.gov.di.ipv.core.library.dto.OauthCriConfig;
import uk.gov.di.ipv.core.library.dto.RestCriConfig;
import uk.gov.di.ipv.core.library.exceptions.ConfigException;
import uk.gov.di.ipv.core.library.exceptions.ConfigParameterNotFoundException;
import uk.gov.di.ipv.core.library.helpers.LogHelper;
import uk.gov.di.ipv.core.library.persistence.item.CriOAuthSessionItem;

import java.io.IOException;
import java.util.Arrays;
import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.stream.Collectors;

import static com.fasterxml.jackson.core.JsonParser.Feature.STRICT_DUPLICATE_DETECTION;

public abstract class ConfigService {
    private static final ObjectMapper OBJECT_MAPPER = new ObjectMapper();
    private static final Logger LOGGER = LogManager.getLogger();
    private static final String PATH_SEPARATOR = "/";
    private static final String FEATURE_SETS = "features";
    private static final String CORE = "core";
    public static final ObjectMapper YAML_OBJECT_MAPPER =
            new ObjectMapper(new YAMLFactory()).configure(STRICT_DUPLICATE_DETECTION, true);

    private Map<String, String> parameters = new HashMap<>();
    @Getter @Setter private Config configuration;

    @Getter @Setter private static boolean local;

    @ExcludeFromGeneratedCoverageReport
    public static ConfigService create() {
        if (isLocal()) {
            return new LocalConfigService();
        }
        return new AppConfigService();
    }

    protected void setParameters(Map<String, String> parameters) {
        this.parameters = parameters;
    }

    public abstract List<String> getFeatureSet();

    protected abstract String getSecret(String path);

    public abstract void setFeatureSet(List<String> featureSet);

    public String getEnvironmentVariable(EnvironmentVariable environmentVariable) {
        return System.getenv(environmentVariable.name());
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

    public String getParameter(String path) {
        if (getFeatureSet() != null) {
            for (String individualFeatureSet : getFeatureSet()) {
                var featurePath =
                        String.format("%s/%s/%s", FEATURE_SETS, individualFeatureSet, path);
                if (parameters.containsKey(featurePath)) {
                    return parameters.get(featurePath);
                }
            }
        }
        if (!parameters.containsKey(path)) {
            throw new ConfigParameterNotFoundException(path);
        }
        return parameters.get(path);
    }

    public Map<String, String> getParametersByPrefix(String path) {
        var lookupParams =
                parameters.entrySet().stream()
                        .filter(e -> e.getKey().startsWith(path))
                        .collect(
                                Collectors.toMap(
                                        entry -> entry.getKey().substring(path.length() + 1),
                                        Map.Entry::getValue));

        if (lookupParams.isEmpty()) {
            throw new ConfigParameterNotFoundException(path);
        }
        return lookupParams;
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

    public OauthCriConfig getOauthCriActiveConnectionConfig(Cri cri) {
        return getOauthCriConfigForConnection(getActiveConnection(cri), cri);
    }

    public OauthCriConfig getOauthCriConfig(CriOAuthSessionItem criOAuthSessionItem) {
        return getOauthCriConfigForConnection(
                criOAuthSessionItem.getConnection(), Cri.fromId(criOAuthSessionItem.getCriId()));
    }

    public OauthCriConfig getOauthCriConfigForConnection(String connection, Cri cri) {
        return getCriConfigForType(cri, connection, OauthCriConfig.class);
    }

    public RestCriConfig getRestCriConfigForConnection(String connection, Cri cri) {
        return getCriConfigForType(cri, connection, RestCriConfig.class);
    }

    public CriConfig getCriConfig(Cri cri) {
        return getCriConfigForType(cri, getActiveConnection(cri), CriConfig.class);
    }

    private <T extends CriConfig> T getCriConfigForType(
            Cri cri, String connection, Class<T> configType) {
        var path =
                formatPath(
                        ConfigurationVariable.CREDENTIAL_ISSUER_CONFIG.getPath(),
                        cri.getId(),
                        connection);
        return getParametersByPrefix(path).entrySet().stream()
                .collect(
                        Collectors.collectingAndThen(
                                Collectors.toMap(
                                        Map.Entry::getKey,
                                        entry ->
                                                unescapeSigEncKey(
                                                        entry.getKey(), entry.getValue())),
                                params -> OBJECT_MAPPER.convertValue(params, configType)));
    }

    private String unescapeSigEncKey(String key, String value) {
        return (key.equals("signingKey") || key.equals("encryptionKey"))
                ? value.replace("\\", "")
                : value;
    }

    public String getActiveConnection(Cri cri) {
        return getParameter(ConfigurationVariable.CREDENTIAL_ISSUER_ACTIVE_CONNECTION, cri.getId());
    }

    public Map<String, ContraIndicatorConfig> getContraIndicatorConfigMap() {
        try {
            var secretValue = getParameter(ConfigurationVariable.CI_SCORING_CONFIG);
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
        var params = getParametersByPrefix(ConfigurationVariable.CIMIT_CONFIG.getPath());
        var parsedData = new HashMap<String, List<MitigationRoute>>();
        for (var entry : params.entrySet()) {
            try {
                var list =
                        OBJECT_MAPPER.readValue(
                                entry.getValue(), new TypeReference<List<MitigationRoute>>() {});
                parsedData.put(entry.getKey(), list);
            } catch (JsonProcessingException e) {
                throw new ConfigException("Failed to parse route for cimit: " + e);
            }
        }
        return parsedData;
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
        var issuerToCri = new HashMap<String, Cri>();
        for (var cri : Cri.values()) {
            if (cri.getId().equals(Cri.CIMIT.getId())) {
                continue;
            }

            var connectionsPath =
                    String.format(
                            ConfigurationVariable.CREDENTIAL_ISSUER_CONNECTION_PREFIX.getPath(),
                            cri.getId());

            try {
                var connections =
                        getParametersByPrefix(connectionsPath).entrySet().stream()
                                .filter(entry -> entry.getKey().endsWith("/componentId"))
                                .collect(Collectors.toMap(Map.Entry::getKey, Map.Entry::getValue));
                connections.values().forEach(value -> issuerToCri.put(value, cri));
            } catch (ConfigParameterNotFoundException e) {
                LOGGER.warn(
                        LogHelper.buildLogMessage(
                                String.format("Issuer for CRI: %s not configured", cri.getId())));
            }
        }
        return issuerToCri;
    }

    protected Map<String, String> updateParameters(String yaml) {
        var map = new HashMap<String, String>();
        try {
            var yamlParsed = YAML_OBJECT_MAPPER.readTree(yaml).get(CORE);
            flattenParameters(map, yamlParsed, "");
            return map;
        } catch (IOException e) {
            throw new IllegalArgumentException("Could not load parameters yaml", e);
        }
    }

    public static Config generateConfiguration(String yaml) {
        try {
            var coreConfig = YAML_OBJECT_MAPPER.readTree(yaml).get(CORE);
            if (coreConfig == null) {
                throw new IllegalArgumentException("Missing Core config.");
            }
            return OBJECT_MAPPER.treeToValue(coreConfig, Config.class);
        } catch (IOException e) {
            throw new IllegalArgumentException("Could not load parameters yaml", e);
        }
    }

    // Helper methods
    private void flattenParameters(Map<String, String> map, JsonNode tree, String prefix) {
        switch (tree.getNodeType()) {
            case BOOLEAN, NUMBER, STRING -> map.put(prefix.substring(1), tree.asText());
            // Required to add CIMIT config which is declared as array in config file
            case ARRAY -> map.put(prefix.substring(1), tree.toString());
            case OBJECT ->
                    tree.properties()
                            .forEach(
                                    entry ->
                                            flattenParameters(
                                                    map,
                                                    entry.getValue(),
                                                    prefix + PATH_SEPARATOR + entry.getKey()));
            case BINARY, MISSING, NULL, POJO ->
                    throw new IllegalArgumentException(
                            String.format(
                                    "Invalid config of type %s at %s", tree.getNodeType(), prefix));
        }
    }

    private String formatPath(String path, String... pathProperties) {
        return String.format(path, (Object[]) pathProperties);
    }
}
