package uk.gov.di.ipv.core.library.domain.cimitvc;

import com.fasterxml.jackson.core.JsonParseException;
import com.fasterxml.jackson.core.JsonParser;
import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.DeserializationContext;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.ObjectReader;
import com.fasterxml.jackson.databind.deser.std.StdDeserializer;

import java.io.IOException;
import java.util.ArrayList;
import java.util.List;

public class EvidenceItemDeserializer extends StdDeserializer<EvidenceItem> {
    private static final ObjectMapper OBJECT_MAPPER = new ObjectMapper();
    private static final ObjectReader STRING_LIST_READER =
            OBJECT_MAPPER.readerFor(new TypeReference<List<String>>() {});
    private static final ObjectReader MITIGATION_LIST_READER =
            OBJECT_MAPPER.readerFor(new TypeReference<List<Mitigation>>() {});
    public static final String CONTRA_INDICATOR = "contraIndicator";
    public static final String DOCUMENT = "document";
    public static final String CODE = "code";
    public static final String ISSUERS = "issuers";
    public static final String ISSUANCE_DATE = "issuanceDate";
    public static final String TXN = "txn";
    public static final String MITIGATION = "mitigation";
    public static final String MITIGATION1 = "incompleteMitigation";
    public static final String TYPE = "type";

    public EvidenceItemDeserializer() {
        this(null);
    }

    protected EvidenceItemDeserializer(Class<?> vc) {
        super(vc);
    }

    @Override
    public EvidenceItem deserialize(JsonParser parser, DeserializationContext ctxt)
            throws IOException {
        JsonNode evidenceNode = parser.getCodec().readTree(parser);

        if (evidenceNode.get(CONTRA_INDICATOR) == null
                || evidenceNode.get(TXN) == null
                || evidenceNode.get(TYPE) == null) {
            throw new JsonParseException("Unexpected null element in evidence node");
        }

        var contraIndicators = new ArrayList<ContraIndicator>();
        for (var ciNode : evidenceNode.get(CONTRA_INDICATOR)) {
            contraIndicators.add(
                    ciNode.get(DOCUMENT).isArray() ? buildV2Ci(ciNode) : buildV1Ci(ciNode));
        }

        return new EvidenceItem(
                evidenceNode.get(TYPE).asText(),
                STRING_LIST_READER.readValue(evidenceNode.get(TXN)),
                contraIndicators);
    }

    private ContraIndicatorV1 buildV1Ci(JsonNode ciNode) throws IOException {
        return ContraIndicatorV1.builder()
                .code(ciNode.get(CODE).asText())
                .issuers(STRING_LIST_READER.readValue(ciNode.get(ISSUERS)))
                .issuanceDate(ciNode.get(ISSUANCE_DATE).asText())
                .document(ciNode.get(DOCUMENT).asText())
                .txn(STRING_LIST_READER.readValue(ciNode.get(TXN)))
                .mitigation(MITIGATION_LIST_READER.readValue(ciNode.get(MITIGATION)))
                .incompleteMitigation(MITIGATION_LIST_READER.readValue(ciNode.get(MITIGATION1)))
                .build();
    }

    private ContraIndicatorV2 buildV2Ci(JsonNode ciNode) throws IOException {
        return ContraIndicatorV2.builder()
                .code(ciNode.get(CODE).asText())
                .issuers(STRING_LIST_READER.readValue(ciNode.get(ISSUERS)))
                .issuanceDate(ciNode.get(ISSUANCE_DATE).asText())
                .document(STRING_LIST_READER.readValue(ciNode.get(DOCUMENT)))
                .txn(STRING_LIST_READER.readValue(ciNode.get(TXN)))
                .mitigation(MITIGATION_LIST_READER.readValue(ciNode.get(MITIGATION)))
                .incompleteMitigation(MITIGATION_LIST_READER.readValue(ciNode.get(MITIGATION1)))
                .build();
    }
}
