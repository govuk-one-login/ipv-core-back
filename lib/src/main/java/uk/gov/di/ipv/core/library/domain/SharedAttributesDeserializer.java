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

        List<String> givenNames = new ArrayList<>();
        JsonNode givenNamesNode = attributes.get("givenNames");
        if (givenNamesNode != null) {
            for (JsonNode name : givenNamesNode) {
                givenNames.add(name.asText());
            }
        }

        JsonNode familyNameNode = attributes.get("familyName");
        String familName = null;
        if (familyNameNode != null) {
            familName = familyNameNode.asText();
        }

        if (!givenNames.isEmpty() || familName != null) {
            sharedAttributesBuilder.setName(new Name(givenNames, familName));
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
