package uk.gov.di.ipv.core.library.service;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.dataformat.yaml.YAMLFactory;
import uk.gov.di.ipv.core.library.exceptions.ConfigParameterNotFoundException;

import java.io.IOException;
import java.util.HashMap;
import java.util.Map;
import java.util.stream.Collectors;

import static com.fasterxml.jackson.core.JsonParser.Feature.STRICT_DUPLICATE_DETECTION;

public abstract class YamlParametersConfigService extends ConfigService {
    private static final String PATH_SEPARATOR = "/";
    private static final String FEATURE_SETS = "features";
    private static final String CORE = "core";
    public static final ObjectMapper YAML_OBJECT_MAPPER =
            new ObjectMapper(new YAMLFactory()).configure(STRICT_DUPLICATE_DETECTION, true);

    public final Map<String, String> parameters = new HashMap<>();

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
    public Map<String, String> getParametersByPrefix(String path) {
        return parameters.entrySet().stream()
                .filter(e -> e.getKey().startsWith(path))
                .collect(
                        Collectors.toMap(
                                e -> e.getKey().substring(path.length()), Map.Entry::getValue));
    }

    protected void updateParameters(Map<String, String> map, String yaml) {
        try {
            var yamlParsed = YAML_OBJECT_MAPPER.readTree(yaml).get(CORE);
            addJsonConfig(map, yamlParsed, "");
        } catch (IOException e) {
            throw new IllegalArgumentException("Could not load parameters yaml", e);
        }
    }

    private void addJsonConfig(Map<String, String> map, JsonNode tree, String prefix) {
        switch (tree.getNodeType()) {
            case BOOLEAN, NUMBER, STRING -> map.put(prefix.substring(1), tree.asText());
            case OBJECT -> tree.fields()
                    .forEachRemaining(
                            entry ->
                                    addJsonConfig(
                                            map,
                                            entry.getValue(),
                                            prefix + PATH_SEPARATOR + entry.getKey()));
            case ARRAY, BINARY, MISSING, NULL, POJO -> throw new IllegalArgumentException(
                    String.format("Invalid config of type %s at %s", tree.getNodeType(), prefix));
        }
    }
}
