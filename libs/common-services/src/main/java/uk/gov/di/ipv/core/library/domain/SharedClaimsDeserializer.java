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
public class SharedClaimsDeserializer extends StdDeserializer<SharedClaims> {

    private final ObjectMapper objectMapper = new ObjectMapper();

    SharedClaimsDeserializer() {
        this(null);
    }

    protected SharedClaimsDeserializer(Class<?> vc) {
        super(vc);
    }

    @Override
    public SharedClaims deserialize(JsonParser jsonParser, DeserializationContext ctxt)
            throws IOException {
        SharedClaims.Builder sharedAttributesBuilder = new SharedClaims.Builder();

        JsonNode node = jsonParser.getCodec().readTree(jsonParser);
        if (node.isEmpty()) {
            return SharedClaims.empty();
        }

        ifExistExtractAndAddName(sharedAttributesBuilder, node);

        ifExistExtractAndAddBirthDate(sharedAttributesBuilder, node);

        ifExistExtractAndAddAddress(sharedAttributesBuilder, node);

        ifExistExtractAndAddSocialSecurityRecord(sharedAttributesBuilder, node);

        return sharedAttributesBuilder.build();
    }

    private void ifExistExtractAndAddName(
            SharedClaims.Builder sharedAttributesBuilder, JsonNode node) {
        JsonNode namesList = node.get("name");
        if (namesList != null) {
            Set<Name> namesSet = new HashSet<>();
            for (JsonNode name : namesList) {
                JsonNode nameParts = name.get("nameParts");
                if (nameParts != null) {
                    List<NameParts> namePartsList = new ArrayList<>();
                    nameParts.forEach(
                            namePart ->
                                    namePartsList.add(
                                            objectMapper.convertValue(namePart, NameParts.class)));
                    namesSet.add(new Name(namePartsList));
                }
            }

            sharedAttributesBuilder.setName(namesSet);
        }
    }

    private void ifExistExtractAndAddBirthDate(
            SharedClaims.Builder sharedAttributesBuilder, JsonNode node) {
        JsonNode dateOfBirth = node.get("birthDate");
        if (dateOfBirth != null) {
            Set<BirthDate> dateList = new HashSet<>();
            for (JsonNode jo : dateOfBirth) {
                dateList.add(objectMapper.convertValue(jo, BirthDate.class));
            }
            sharedAttributesBuilder.setBirthDate(dateList);
        }
    }

    private void ifExistExtractAndAddAddress(
            SharedClaims.Builder sharedAttributesBuilder, JsonNode node) {
        JsonNode address = node.get("address");
        if (address != null) {
            Set<Address> addressList = new HashSet<>();
            for (JsonNode jo : address) {
                addressList.add(objectMapper.convertValue(jo, Address.class));
            }
            sharedAttributesBuilder.setAddress(addressList);
        }
    }

    private void ifExistExtractAndAddSocialSecurityRecord(
            SharedClaims.Builder sharedAttributesBuilder, JsonNode node) {
        JsonNode socialSecurityRecord = node.get("socialSecurityRecord");
        if (socialSecurityRecord != null) {
            Set<SocialSecurityRecord> socialSecurityRecordList = new HashSet<>();
            for (JsonNode jo : socialSecurityRecord) {
                socialSecurityRecordList.add(
                        objectMapper.convertValue(jo, SocialSecurityRecord.class));
            }
            sharedAttributesBuilder.setSocialSecurityRecord(socialSecurityRecordList);
        }
    }
}
