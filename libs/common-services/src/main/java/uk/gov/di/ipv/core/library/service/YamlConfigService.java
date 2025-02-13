package uk.gov.di.ipv.core.library.service;

import java.io.File;
import java.io.IOException;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

public class YamlConfigService extends YamlParametersConfigService {
    private static final File PARAMETERS_FILE = new File("./core.local.params.yaml");
    private static final File SECRETS_FILE = new File("./core.local.secrets.yaml");
    private static final String CORE = "core";
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

    private final Map<String, String> secrets = new HashMap<>();

    public YamlConfigService() {
        this(PARAMETERS_FILE, SECRETS_FILE);
    }

    public YamlConfigService(File parametersFile, File secretsFile) {
        try {
            var paramsYaml = YAML_OBJECT_MAPPER.readTree(parametersFile).get(CORE);
            var secretsYaml = YAML_OBJECT_MAPPER.readTree(secretsFile).get(CORE);

            addJsonConfig(parameters, paramsYaml);
            addJsonConfig(secrets, secretsYaml);
        } catch (IOException e) {
            throw new IllegalArgumentException("Could not load parameter files", e);
        }
    }

    @Override
    public String getParameter(String path) {
        return this.getParameterFromStoredValue(path);
    }

    @Override
    public Map<String, String> getParametersByPrefix(String path) {
        return this.getParametersFromStoredValueByPrefix(path);
    }

    @Override
    public String getSecret(String path) {
        return secrets.get(path);
    }
}
