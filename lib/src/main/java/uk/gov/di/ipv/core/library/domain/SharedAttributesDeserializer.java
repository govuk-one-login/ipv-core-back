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
            JsonNode familyName = names.get("familyName");
            if (familyName != null) {
                sharedAttributesBuilder.setName(new Name(givenNames, familyName.asText()));
            }
        }

        JsonNode dateOfBirth = attributes.get("dateOfBirth");
        if (dateOfBirth != null) {
            sharedAttributesBuilder.setDateOfBirth(dateOfBirth.asText());
        }

        JsonNode address = attributes.get("address");
        if (address != null) {
            sharedAttributesBuilder.setAddress(
                    objectMapper.convertValue(address, new TypeReference<>() {}));
        }

        JsonNode addressHistory = attributes.get("addressHistory");
        if (addressHistory != null) {
            sharedAttributesBuilder.setAddressHistory(
                    objectMapper.convertValue(addressHistory, new TypeReference<>() {}));
        }

        return sharedAttributesBuilder.build();
    }
}
