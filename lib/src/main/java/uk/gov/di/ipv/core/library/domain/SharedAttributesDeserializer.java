package uk.gov.di.ipv.core.library.domain;

import com.fasterxml.jackson.core.JsonParser;
import com.fasterxml.jackson.databind.DeserializationContext;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.deser.std.StdDeserializer;
import uk.gov.di.ipv.core.library.annotations.ExcludeFromGeneratedCoverageReport;

import java.io.IOException;
import java.util.ArrayList;
import java.util.HashSet;
import java.util.List;
import java.util.Set;

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
        if (node.isEmpty()) {
            return SharedAttributes.empty();
        }

        JsonNode nameNode = node.get("name");
        if (nameNode != null) {
            Set<Name> nameList = new HashSet<>();
            List<NameParts> namePartsList = new ArrayList<>();

            for (JsonNode jo : nameNode) {
                JsonNode nameParts = jo.get("nameParts");
                if (nameParts != null) {
                    nameParts.forEach(
                            namePart ->
                                    namePartsList.add(
                                            objectMapper.convertValue(namePart, NameParts.class)));
                }
            }

            Name names = new Name(namePartsList);
            nameList.add(names);
            sharedAttributesBuilder.setName(nameList);
        }

        JsonNode dateOfBirth = node.get("birthDate");
        if (dateOfBirth != null) {
            Set<BirthDate> dateList = new HashSet<>();
            for (JsonNode jo : dateOfBirth) {
                dateList.add(objectMapper.convertValue(jo, BirthDate.class));
            }
            sharedAttributesBuilder.setBirthDate(dateList);
        }

        JsonNode address = node.get("address");
        if (address != null) {
            Set<Address> addressList = new HashSet<>();
            for (JsonNode jo : address) {
                addressList.add(objectMapper.convertValue(jo, Address.class));
            }
            sharedAttributesBuilder.setAddress(addressList);
        }

        return sharedAttributesBuilder.build();
    }
}
