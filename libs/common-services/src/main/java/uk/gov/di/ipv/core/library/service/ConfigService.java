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

import java.io.IOException;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.stream.Collectors;

import static com.fasterxml.jackson.core.JsonParser.Feature.STRICT_DUPLICATE_DETECTION;
import java.util.Objects;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import java.util.stream.Collectors;

public abstract class ConfigService {
    private static final ObjectMapper OBJECT_MAPPER = new ObjectMapper();
    private static final Logger LOGGER = LogManager.getLogger();
    private static final String PATH_SEPARATOR = "/";
    private static final String FEATURE_SETS = "features";
    private static final String CORE = "core";
    public static final ObjectMapper YAML_OBJECT_MAPPER =
            new ObjectMapper(new YAMLFactory()).configure(STRICT_DUPLICATE_DETECTION, true);

    public final Map<String, String> parameters = new HashMap<>();

    @Getter @Setter private static boolean local = false;

    @ExcludeFromGeneratedCoverageReport
    public static ConfigService create() {
        if (isLocal()) {
            return new YamlConfigService();
        }
        return new AppConfigService();
    }

    public abstract List<String> getFeatureSet();

    protected abstract Map<String, String> getParametersByPrefixYaml(String path);

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
        return parameters.entrySet().stream()
                .filter(e -> e.getKey().startsWith(path))
                .collect(
                        Collectors.toMap(
                                e -> e.getKey().substring(path.length()), Map.Entry::getValue));
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
        return getCriConfigForType(connection, cri, OauthCriConfig.class);
    }

    public RestCriConfig getRestCriConfigForConnection(String connection, Cri cri) {
        return getCriConfigForType(connection, cri, RestCriConfig.class);
    }

    public CriConfig getCriConfig(Cri cri) {
        return getCriConfigForType(getActiveConnection(cri), cri, CriConfig.class);
    }

    private <T extends CriConfig> T getCriConfigForType(
            String connection, Cri cri, Class<T> configType) {
        if (isConfigInYaml()) {
            return getCriConfigForTypeInYaml(cri, connection, configType);
        }

        String criId = cri.getId();
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

    private <T extends CriConfig> T getCriConfigForTypeInYaml(
            Cri cri, String connection, Class<T> configType) {
        var path =
                formatPath(
                        ConfigurationVariable.CREDENTIAL_ISSUER_CONFIG.getPath(),
                        cri.getId(),
                        connection);
        return getParametersByPrefixYaml(path).entrySet().stream()
                .collect(
                        Collectors.collectingAndThen(
                                Collectors.toMap(
                                        Map.Entry::getKey,
                                        entry ->
                                                unescapeSigEncKey(
                                                        entry.getKey(), entry.getValue())),
                                parameters -> OBJECT_MAPPER.convertValue(parameters, configType)));
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
        if (isConfigInYaml()) {
            return getCimitConfigInYaml();
        }

        final String cimitConfig = getParameter(ConfigurationVariable.CIMIT_CONFIG);
        try {
            return OBJECT_MAPPER.readValue(
                    cimitConfig, new TypeReference<HashMap<String, List<MitigationRoute>>>() {});
        } catch (JsonProcessingException e) {
            throw new ConfigException("Failed to parse CIMit configuration");
        }
    }

    private Map<String, List<MitigationRoute>> getCimitConfigInYaml() throws ConfigException {
        var parameters = getParametersByPrefixYaml(ConfigurationVariable.CIMIT_CONFIG.getPath());
        var parsedData = new HashMap<String, List<MitigationRoute>>();
        for (var entry : parameters.entrySet()) {
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
        if (isConfigInYaml()) {
            return getIssuerCrisYaml();
        }

        var allCriParameters = getParametersByPrefix("credentialIssuers");
        var issuerToCriMap = new HashMap<String, Cri>();

        for (Map.Entry<String, String> entry : allCriParameters.entrySet()) {
            var fullPath = entry.getKey();
            var value = entry.getValue();

            var cri = findCriFromPath(fullPath);
            if (cri == null) continue;

            try {
                var criConfig = OBJECT_MAPPER.readValue(value, CriConfig.class);
                var issuer = criConfig.getComponentId();
                issuerToCriMap.put(issuer, cri);
            } catch (JsonProcessingException e) {
                throw new ConfigParseException(
                        String.format(
                                "Failed to parse credential issuer configuration at path '%s': %s",
                                fullPath, e));
            }
        }
        return issuerToCriMap;
    }

    private Map<String, Cri> getIssuerCrisYaml() {
        var issuerToCri = new HashMap<String, Cri>();
        for (var cri : Cri.values()) {
            if (cri.getId().equals(Cri.CIMIT.getId())) {
                continue;
            }
            try {
                var connection = getActiveConnection(cri);
                var path =
                        String.format(
                                ConfigurationVariable.CREDENTIAL_ISSUER_COMPONENT_ID.getPath(),
                                cri.getId(),
                                connection);
                var componentId = getParameter(path);
                issuerToCri.put(componentId, cri);
            } catch (ConfigParameterNotFoundException e) {
                LOGGER.warn(
                        LogHelper.buildLogMessage(
                                String.format("Issuer for CRI: %s not configured", cri.getId())));
            }
        }
        return issuerToCri;
    }

    private Cri findCriFromPath(String parameterPath) {
        Pattern pattern = Pattern.compile("([^/]+)/connections");
        Matcher matcher = pattern.matcher(parameterPath);

        if (matcher.find()) {
            try {
                return Cri.fromId(matcher.group(1));
            } catch (IllegalArgumentException e) {
                return null;
            }
        }
        return null;
    }

    private boolean isConfigInYaml() {
        var path = "self/configFormat";
        return getParameter(path).equals("yaml");
    }

    protected void updateParameters(Map<String, String> map, String yaml) {
        try {
            var yamlParsed = YAML_OBJECT_MAPPER.readTree(yaml).get(CORE);
            addJsonConfig(map, yamlParsed, "");
        } catch (IOException e) {
            throw new IllegalArgumentException("Could not load parameters yaml", e);
        }
    }

    // Helper methods
    private void addJsonConfig(Map<String, String> map, JsonNode tree, String prefix) {
        switch (tree.getNodeType()) {
            case BOOLEAN, NUMBER, STRING -> map.put(prefix.substring(1), tree.asText());
            case OBJECT ->
                    tree.properties()
                            .forEach(
                                    entry ->
                                            addJsonConfig(
                                                    map,
                                                    entry.getValue(),
                                                    prefix + PATH_SEPARATOR + entry.getKey()));
            case ARRAY, BINARY, MISSING, NULL, POJO ->
                    throw new IllegalArgumentException(
                            String.format(
                                    "Invalid config of type %s at %s", tree.getNodeType(), prefix));
        }
    }

    private String formatPath(String path, String... pathProperties) {
        return String.format(path, (Object[]) pathProperties);
    }
}
