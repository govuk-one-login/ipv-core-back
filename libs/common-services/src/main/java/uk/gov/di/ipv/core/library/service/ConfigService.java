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
import uk.gov.di.ipv.core.library.config.domain.CiRoutingConfig;
import uk.gov.di.ipv.core.library.config.domain.Config;
import uk.gov.di.ipv.core.library.domain.ContraIndicatorConfig;
import uk.gov.di.ipv.core.library.domain.Cri;
import uk.gov.di.ipv.core.library.dto.OauthCriConfig;
import uk.gov.di.ipv.core.library.dto.RestCriConfig;
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

    public String getParameter( // TO BE REMOVED
            ConfigurationVariable configurationVariable, String... pathProperties) {
        return getParameter(formatPath(configurationVariable.getPath(), pathProperties));
    }

    public String getParameter(String path) { // TO BE REMOVED
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

    public boolean isCredentialIssuerEnabled(String criId) {
        if (criId == null) return false;

        var cfg = getConfiguration();
        var wrapper = cfg.getCredentialIssuers().getById(criId);
        return wrapper != null && Boolean.parseBoolean(wrapper.getEnabled());
    }

    public long getLongParameter( // TO BE REMOVED
            ConfigurationVariable configurationVariable, String... pathProperties) {
        return Long.parseLong(getParameter(configurationVariable, pathProperties));
    }

    public long getBackendSessionTimeout() {
        return getConfiguration().getSelf().getBackendSessionTimeout();
    }

    public long getOauthKeyCacheDurationMins() {
        return getConfiguration().getSelf().getOauthKeyCacheDurationMins();
    }

    public long getBearerTokenTtl() {
        return getConfiguration().getSelf().getBearerTokenTtl();
    }

    public long getJwtTtlSeconds() {
        return getConfiguration().getSelf().getJwtTtlSeconds();
    }

    public long getAuthCodeExpirySeconds() {
        return getConfiguration().getSelf().getAuthCodeExpirySeconds();
    }

    public long getMaxAllowedAuthClientTtl() {
        return getConfiguration().getSelf().getMaxAllowedAuthClientTtl();
    }

    public List<String> getClientValidRedirectUrls(String clientId) {
        var clientConfigValidRedirectUrs =
                getConfiguration().getClientConfig(clientId).getValidRedirectUrls();
        return Arrays.asList(clientConfigValidRedirectUrs.split("\\s*,\\s*"));
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
        return OBJECT_MAPPER.convertValue(
                getConfiguration()
                        .getCredentialIssuers()
                        .getById(cri.getId())
                        .getConnections()
                        .get(connection),
                OauthCriConfig.class);
    }

    public RestCriConfig getRestCriConfigForConnection(String connection, Cri cri) {
        return OBJECT_MAPPER.convertValue(
                getConfiguration()
                        .getCredentialIssuers()
                        .getById(cri.getId())
                        .getConnections()
                        .get(connection),
                RestCriConfig.class);
    }

    public String getActiveConnection(Cri cri) {
        return getConfiguration().getCredentialIssuers().getById(cri.getId()).getActiveConnection();
    }

    public Map<String, ContraIndicatorConfig> getContraIndicatorConfigMap() {
        try {
            var secretValue = getConfiguration().getSelf().getCiScoringConfig().toString();
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

    public Map<String, List<CiRoutingConfig>> getCimitConfig() {
        return getConfiguration().getCimit().getConfig();
    }

    public boolean enabled(FeatureFlag flag) {
        return enabled(flag.getName());
    }

    public boolean enabled(String flagName) {
        var cfg = getConfiguration();
        var flags = (cfg != null) ? cfg.getFeatureFlags() : null;
        return flags != null && Boolean.TRUE.equals(flags.get(flagName));
    }

    public Map<String, Cri> getIssuerCris() {
        var issuerToCri = new HashMap<String, Cri>();
        for (var cri : Cri.values()) {
            if (cri.getId().equals(Cri.CIMIT.getId())) continue;
            var wrapper = getConfiguration().getCredentialIssuers().getById(cri.getId());
            var connections = (wrapper != null) ? wrapper.getConnections() : null;
            if (connections == null || connections.isEmpty()) {
                LOGGER.warn(
                        LogHelper.buildLogMessage(
                                "Issuer for CRI: %s not configured".formatted(cri.getId())));
                continue;
            }
            for (var conn : connections.values()) {
                var componentId = conn.getComponentId();
                if (componentId != null && !componentId.isBlank())
                    issuerToCri.put(componentId, cri);
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
