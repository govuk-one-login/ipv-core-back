package uk.gov.di.ipv.core.library.helpers;

import com.fasterxml.jackson.core.JsonParser;
import com.fasterxml.jackson.databind.DeserializationContext;
import com.fasterxml.jackson.databind.JsonDeserializer;

import java.io.IOException;

public class RemoveEscapedQuotesDeserializer extends JsonDeserializer<String> {
    @Override
    public String deserialize(JsonParser p, DeserializationContext ctxt) throws IOException {
        String raw = p.getValueAsString();
        if (raw == null) {
            return null;
        }

        // If the string is like {\"kty\":\"EC\"...}, unescape it
        if (raw.contains("\\\"")) {
            return raw.replace("\\\"", "\"");
        }

        return raw;
    }
}
