package uk.gov.di.ipv.core.library.service;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ObjectNode;
import com.fasterxml.jackson.dataformat.yaml.YAMLFactory;
import uk.gov.di.ipv.core.library.annotations.ExcludeFromGeneratedCoverageReport;
import uk.gov.di.ipv.core.library.exceptions.ConfigParameterNotFoundException;

import java.io.File;
import java.io.IOException;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.stream.Collectors;

import static com.fasterxml.jackson.core.JsonParser.Feature.STRICT_DUPLICATE_DETECTION;

public class YamlConfigService extends ConfigService {
    private static final File PARAMETERS_FILE = new File("./core.local.params.yaml");
    private static final File SECRETS_FILE = new File("./core.local.secrets.yaml");
    private static final File API_TEST_CONFIG = new File("./core.api-tests.params.yaml");
    private static final String PATH_SEPARATOR = "/";
    private static final String CORE = "core";
    private static final String CLIENTS = "clients";
    private static final String FEATURE_SETS = "features";
    private final ThreadLocal<List<String>> featureSet = new ThreadLocal<>();

    public List<String> getFeatureSet() {
        return featureSet.get();
    }

    public void setFeatureSet(List<String> featureSet) {
        this.featureSet.set(featureSet);
    }

    public void removeFeatureSet() {
        this.featureSet.remove();
    }

    private static final ObjectMapper YAML_OBJECT_MAPPER =
            new ObjectMapper(new YAMLFactory()).configure(STRICT_DUPLICATE_DETECTION, true);

    private final Map<String, String> parameters = new HashMap<>();
    private final Map<String, String> secrets = new HashMap<>();

    public YamlConfigService(boolean useApiTestConfig) {
        if (useApiTestConfig) {
            addParamsAndSecretsToConfig(PARAMETERS_FILE, SECRETS_FILE, API_TEST_CONFIG);
        }
        addParamsAndSecretsToConfig(PARAMETERS_FILE, SECRETS_FILE, null);
    }

    public YamlConfigService() {
        addParamsAndSecretsToConfig(PARAMETERS_FILE, SECRETS_FILE, null);
    }

    @ExcludeFromGeneratedCoverageReport
    public YamlConfigService(File parametersFile, File secretsFile, File apiTestConfig) {
        addParamsAndSecretsToConfig(parametersFile, secretsFile, apiTestConfig);
    }

    private void addParamsAndSecretsToConfig(
            File parametersFile, File secretsFile, File apiTestConfig) {
        try {
            var paramsYaml = getParamsWithCorrectClientConfig(parametersFile, apiTestConfig);
            var secretsYaml = YAML_OBJECT_MAPPER.readTree(secretsFile).get(CORE);

            addConfig(parameters, paramsYaml);
            addConfig(secrets, secretsYaml);
        } catch (IOException e) {
            throw new IllegalArgumentException("Could not load parameter files", e);
        }
    }

    private JsonNode getParamsWithCorrectClientConfig(File parametersFile, File apiClientConfigFile)
            throws IOException {
        try {
            var params = YAML_OBJECT_MAPPER.readTree(parametersFile).get(CORE);

            if (apiClientConfigFile != null) {
                var apiClientConfig = YAML_OBJECT_MAPPER.readTree(apiClientConfigFile).get(CLIENTS);
                ((ObjectNode) params).replace(CLIENTS, apiClientConfig);
            }

            return params;
        } catch (IOException e) {
            throw new IllegalArgumentException("Could not load parameter files", e);
        }
    }

    private void addConfig(Map<String, String> map, JsonNode tree) {
        addConfig(map, tree, "");
    }

    private void addConfig(Map<String, String> map, JsonNode tree, String prefix) {
        switch (tree.getNodeType()) {
            case BOOLEAN, NUMBER, STRING -> map.put(prefix.substring(1), tree.asText());
            case OBJECT -> tree.fields()
                    .forEachRemaining(
                            entry ->
                                    addConfig(
                                            map,
                                            entry.getValue(),
                                            prefix + PATH_SEPARATOR + entry.getKey()));
            case ARRAY, BINARY, MISSING, NULL, POJO -> throw new IllegalArgumentException(
                    String.format("Invalid config of type %s at %s", tree.getNodeType(), prefix));
        }
    }

    @Override
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

    @Override
    protected Map<String, String> getParametersByPrefix(String path) {
        return parameters.entrySet().stream()
                .filter(e -> e.getKey().startsWith(path))
                .collect(
                        Collectors.toMap(
                                e -> e.getKey().substring(path.length()), Map.Entry::getValue));
    }

    @Override
    public String getSecret(String path) {
        return secrets.get(path);
    }
}
