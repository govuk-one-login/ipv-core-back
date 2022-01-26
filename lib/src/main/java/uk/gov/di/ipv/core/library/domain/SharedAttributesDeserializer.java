package uk.gov.di.ipv.core.library.domain;

import com.fasterxml.jackson.core.JsonParser;
import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.DeserializationContext;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.deser.std.StdDeserializer;
import uk.gov.di.ipv.core.library.annotations.ExcludeFromGeneratedCoverageReport;

import java.io.IOException;
import java.util.ArrayList;
import java.util.List;

@ExcludeFromGeneratedCoverageReport
public class SharedAttributesDeserializer extends StdDeserializer<SharedAttributes> {

    private final ObjectMapper objectMapper = new ObjectMapper();

    SharedAttributesDeserializer() {
        this(null);
    }

    protected SharedAttributesDeserializer(Class<?> vc) {
        super(vc);
    }

    @Override
    public SharedAttributes deserialize(JsonParser jsonParser, DeserializationContext ctxt)
            throws IOException {

        SharedAttributes.Builder sharedAttributesBuilder = new SharedAttributes.Builder();

        JsonNode node = jsonParser.getCodec().readTree(jsonParser);

        JsonNode attributes = node.get("attributes");
        if (attributes == null) {
            return SharedAttributes.empty();
        }

        JsonNode names = attributes.get("names");
        if (names != null) {
            List<String> givenNames = new ArrayList<>();
            for (JsonNode name : names.get("givenNames")) {
                givenNames.add(name.asText());
            }
            sharedAttributesBuilder.setName(new Name(givenNames, names.get("familyName").asText()));
        }

        sharedAttributesBuilder.setDateOfBirth(attributes.get("dateOfBirth").asText());
        sharedAttributesBuilder.setAddress(
                objectMapper.convertValue(attributes.get("address"), new TypeReference<>() {}));
        sharedAttributesBuilder.setAddressHistory(
                objectMapper.convertValue(
                        attributes.get("addressHistory"), new TypeReference<>() {}));
        return sharedAttributesBuilder.build();
    }
}
