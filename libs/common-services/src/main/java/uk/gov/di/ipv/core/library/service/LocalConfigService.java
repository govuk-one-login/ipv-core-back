package uk.gov.di.ipv.core.library.service;

import uk.gov.di.ipv.core.library.annotations.ExcludeFromGeneratedCoverageReport;

import java.io.File;
import java.io.IOException;
import java.nio.file.Files;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

public class LocalConfigService extends ConfigService {
    private static final File PARAMETERS_FILE = new File("./core.local.params.yaml");
    private static final File SECRETS_FILE = new File("./core.local.secrets.yaml");
    private final ThreadLocal<List<String>> featureSet = new ThreadLocal<>();

    @ExcludeFromGeneratedCoverageReport
    public LocalConfigService() {
        this(PARAMETERS_FILE, SECRETS_FILE);
    }

    @ExcludeFromGeneratedCoverageReport
    public LocalConfigService(File parametersFile, File secretsFile) {
        secrets = updateParameters(parseYamlFile(secretsFile));

        var yaml = parseYamlFile(parametersFile);

        setConfiguration(generateConfiguration(yaml));
    }

    @ExcludeFromGeneratedCoverageReport
    public LocalConfigService(String parametersYaml, String secretsYaml) {
        secrets = updateParameters(secretsYaml);

        setConfiguration(generateConfiguration(parametersYaml));
    }

    @Override
    @SuppressWarnings("java:S1186") // Sonar: Methods should not be empty
    public void reloadParameters() {
        // Intentionally no-op for LocalConfigService:
        // config is loaded from provided local/test YAML and does not change at runtime.
        // AppConfigService overrides this to fetch fresh values.
    }

    public void removeFeatureSet() {
        this.featureSet.remove();
    }

    public List<String> getFeatureSet() {
        return featureSet.get();
    }

    public void setFeatureSet(List<String> featureSet) {
        this.featureSet.set(featureSet);
    }

    private Map<String, String> secrets = new HashMap<>();

    private String parseYamlFile(File yamlFile) {
        try {
            return Files.readString(yamlFile.toPath());
        } catch (IOException e) {
            throw new IllegalArgumentException("Could not read parameters yaml file", e);
        }
    }

    @Override
    public String getSecret(String path) {
        return secrets.get(path);
    }
}
