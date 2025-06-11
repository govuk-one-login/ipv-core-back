package uk.gov.di.ipv.core.library.service;

import java.io.File;
import java.io.IOException;
import java.nio.file.Files;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

public class YamlConfigService extends ConfigService {
    private static final File PARAMETERS_FILE = new File("./core.local.params.yaml");
    private static final File SECRETS_FILE = new File("./core.local.secrets.yaml");
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

    private Map<String, String> secrets = new HashMap<>();

    public YamlConfigService() {
        this(PARAMETERS_FILE, SECRETS_FILE);
    }

    public YamlConfigService(File parametersFile, File secretsFile) {
        setParameters(parseParameters(parametersFile));
        secrets = parseParameters(secretsFile);
    }

    private Map<String, String> parseParameters(File yamlFile) {
        try {
            String yamlContent = Files.readString(yamlFile.toPath());
            return parseParameters(yamlContent);
        } catch (IOException e) {
            throw new IllegalArgumentException("Could not read parameters yaml file", e);
        }
    }

    @Override
    public String getSecret(String path) {
        return secrets.get(path);
    }
}
