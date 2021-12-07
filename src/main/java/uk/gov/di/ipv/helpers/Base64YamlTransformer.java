package uk.gov.di.ipv.helpers;

import com.amazonaws.util.Base64;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.dataformat.yaml.YAMLFactory;
import com.fasterxml.jackson.dataformat.yaml.YAMLParser;
import software.amazon.lambda.powertools.parameters.exception.TransformationException;
import software.amazon.lambda.powertools.parameters.transform.Transformer;

import java.io.IOException;

public class Base64YamlTransformer<T> implements Transformer<T> {

    @Override
    public T applyTransformation(String base64Yaml, Class<T> targetClass) throws TransformationException {
        YAMLFactory yamlFactory = new YAMLFactory();
        try {
            YAMLParser yamlParser = yamlFactory.createParser(Base64.decode(base64Yaml));
            return new ObjectMapper(yamlFactory).readValue(yamlParser, targetClass);
        } catch (IOException e) {
            throw new TransformationException(e);
        }
    }
}
