package uk.gov.di.ipv.core.library.service;

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
import uk.gov.di.ipv.core.library.dto.CriConfig;
import uk.gov.di.ipv.core.library.dto.OauthCriConfig;
import uk.gov.di.ipv.core.library.dto.RestCriConfig;
import uk.gov.di.ipv.core.library.exceptions.ConfigParseException;
import uk.gov.di.ipv.core.library.helpers.LogHelper;
import uk.gov.di.ipv.core.library.persistence.item.CriOAuthSessionItem;

import java.io.IOException;
import java.net.URI;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.function.Function;
import java.util.regex.Pattern;
import java.util.stream.Collectors;

import static com.fasterxml.jackson.core.JsonParser.Feature.STRICT_DUPLICATE_DETECTION;

public abstract class ConfigService {
    private static final ObjectMapper OBJECT_MAPPER = new ObjectMapper();
    private static final Logger LOGGER = LogManager.getLogger();
    private static final String PATH_SEPARATOR = "/";
    private static final String CORE = "core";
    public static final ObjectMapper YAML_OBJECT_MAPPER =
            new ObjectMapper(new YAMLFactory()).configure(STRICT_DUPLICATE_DETECTION, true);

    @Setter private Config configuration;

    @Getter @Setter private static boolean local;

    @ExcludeFromGeneratedCoverageReport
    public static ConfigService create() {
        if (isLocal()) {
            return new LocalConfigService();
        }
        return new AppConfigService();
    }

    public abstract List<String> getFeatureSet();

    protected abstract String getSecret(String path);

    public abstract void setFeatureSet(List<String> featureSet);

    public Config getConfiguration() {
        reloadParameters();

        var featureSets = getFeatureSet();
        if (featureSets != null) {
            return overrideConfiguration(featureSets);
        }

        return configuration;
    }

    private Config overrideConfiguration(List<String> featureSets) {
        var features = configuration.getFeatures();

        var configNode = OBJECT_MAPPER.valueToTree(configuration);
        var reader = OBJECT_MAPPER.readerForUpdating(configNode);
        try {
            for (var featureSetName : featureSets) {
                var override = OBJECT_MAPPER.valueToTree(features.get(featureSetName));
                reader.readValue(override);
            }
            return OBJECT_MAPPER.convertValue(configNode, Config.class);
        } catch (IOException e) {
            throw new ConfigParseException("Feature set overrides cannot be read", e);
        }
    }

    public void reloadParameters() {
        // Real fetch & parse happens in AppConfigService, while LocalConfigService is static.
    }

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

    public boolean isCredentialIssuerEnabled(String criId) {
        var wrapper = getConfiguration().getCredentialIssuers().getById(criId);
        return wrapper != null && Boolean.parseBoolean(wrapper.getEnabled());
    }

    public long getBackendSessionTtl() {
        return getConfiguration().getSelf().getBackendSessionTtl();
    }

    public long getDcmawAsyncVcPendingReturnTtl() {
        return getConfiguration().getSelf().getDcmawAsyncVcPendingReturnTtl();
    }

    public long getCriResponseTtl() {
        return getConfiguration().getSelf().getCriResponseTtl();
    }

    public long getSessionCredentialTtl() {
        return getConfiguration().getSelf().getSessionCredentialTtl();
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

    public String getComponentId() {
        return getConfiguration().getSelf().getComponentId().toString();
    }

    public String getSisComponentId() {
        return getConfiguration().getStoredIdentityService().getComponentId().toString();
    }

    public String getCimitComponentId() {
        return getConfiguration().getCimit().getComponentId().toString();
    }

    public String getAllowedSharedAttributes(Cri cri) {
        return getConfiguration()
                .getCredentialIssuers()
                .getById(cri.getId())
                .getAllowedSharedAttributes();
    }

    public String getValidScopes(String clientId) {
        return getConfiguration().getClientConfig(clientId).getValidScopes();
    }

    public String getIssuer(String clientId) {
        return getConfiguration().getClientConfig(clientId).getIssuer();
    }

    public Integer getFraudCheckExpiryPeriodHours() {
        return getConfiguration().getSelf().getFraudCheckExpiryPeriodHours();
    }

    public URI getSisApplicationUrl() {
        return getConfiguration().getSis().getApplicationUrl();
    }

    public String getCoreVtmClaim() {
        return getConfiguration().getSelf().getCoreVtmClaim().toString();
    }

    public long getAuthCodeExpirySeconds() {
        return getConfiguration().getSelf().getAuthCodeExpirySeconds();
    }

    public long getMaxAllowedAuthClientTtl() {
        return getConfiguration().getSelf().getMaxAllowedAuthClientTtl();
    }

    private static final Pattern COMMA = Pattern.compile(",");

    public List<String> getClientValidRedirectUrls(String clientId) {
        var urls = getConfiguration().getClientConfig(clientId).getValidRedirectUrls();
        if (urls.isBlank()) {
            return List.of();
        }
        return COMMA.splitAsStream(urls).map(String::trim).filter(s -> !s.isEmpty()).toList();
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
        var list = getConfiguration().getSelf().getCiScoringConfig();
        if (list.isEmpty()) return Map.of();

        return list.stream()
                .collect(
                        Collectors.toMap(
                                ContraIndicatorConfig::getCi,
                                Function.identity(),
                                (first, second) -> second,
                                HashMap::new));
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
        var issuers = getConfiguration().getCredentialIssuers();

        for (var cri : Cri.values()) {
            if (Cri.CIMIT.getId().equals(cri.getId())) {
                continue; // skip CIMIT early to avoid nesting
            }

            var wrapper = issuers.getById(cri.getId());
            var connections = (wrapper != null) ? wrapper.getConnections() : null;

            addIssuerMappings(issuerToCri, cri, connections);
        }
        return issuerToCri;
    }

    private void addIssuerMappings(
            Map<String, Cri> out, Cri cri, Map<String, ? extends CriConfig> connections) {

        if (connections == null || connections.isEmpty()) {
            LOGGER.warn(
                    LogHelper.buildLogMessage(
                            "Issuer for CRI: %s not configured".formatted(cri.getId())));
            return;
        }

        for (var conn : connections.values()) {
            var componentId = conn.getComponentId();
            if (componentId != null && !componentId.isBlank()) {
                out.put(componentId, cri);
            }
        }
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
            LOGGER.info(yaml);
            var core = YAML_OBJECT_MAPPER.readTree(yaml).get(CORE);
            if (core == null) throw new IllegalArgumentException("Missing Core config.");
            return OBJECT_MAPPER.treeToValue(core, Config.class);
        } catch (IOException e) {
            throw new IllegalArgumentException("Could not load parameters yaml", e);
        }
    }

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
