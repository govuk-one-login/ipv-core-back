package uk.gov.di.ipv.core.library.serializers;

import com.fasterxml.jackson.core.JsonParser;
import com.fasterxml.jackson.databind.DeserializationContext;
import com.fasterxml.jackson.databind.JsonDeserializer;

import java.io.IOException;

/** Keeps json value as json, does not try to deserialize it */
public class KeepAsJsonDeserializer extends JsonDeserializer<String> {

    @Override
    public String deserialize(JsonParser jp, DeserializationContext ctxt) throws IOException {

        String tree = jp.getCodec().readTree(jp).toString();
        // Escape double quotes and backslash for backwards compatibility with old parameters
        if (tree != null
                && tree.length() >= 2
                && tree.charAt(0) == '\"'
                && tree.charAt(tree.length() - 1) == '\"') {
            return tree.substring(1, tree.length() - 1).replace("\\", "");
        }
        return tree;
    }
}
