package uk.gov.di.ipv.core.library.domain;

import com.fasterxml.jackson.annotation.JsonInclude;
import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Getter;
import lombok.extern.jackson.Jacksonized;
import uk.gov.di.ipv.core.library.annotations.ExcludeFromGeneratedCoverageReport;

import java.util.Base64;
import java.util.HashMap;
import java.util.Map;

@Getter
@Builder
@Jacksonized
@AllArgsConstructor
@ExcludeFromGeneratedCoverageReport
@JsonInclude(JsonInclude.Include.NON_NULL)
public class EvidenceRequest {
    public static final String SCORING_POLICY_GPG45 = "gpg45";

    private static final ObjectMapper objectMapper = new ObjectMapper();

    private final String scoringPolicy;
    private final Integer strengthScore;
    private final Integer verificationScore;

    // The JSON serialiser used by the Nimbus JWT library includes null values within claims so we
    // need to have a way of giving it the values without including nulls. This is far from ideal.
    public Map<String, Object> toMapWithNoNulls() {
        var map = new HashMap<String, Object>();

        if (scoringPolicy != null) {
            map.put("scoringPolicy", scoringPolicy);
        }
        if (strengthScore != null) {
            map.put("strengthScore", strengthScore);
        }
        if (verificationScore != null) {
            map.put("verificationScore", verificationScore);
        }

        return map;
    }

    public String toBase64() throws JsonProcessingException {
        var jsonString = objectMapper.writeValueAsString(this);
        var jsonBytes = jsonString.getBytes();
        return Base64.getEncoder().encodeToString(jsonBytes);
    }

    public static EvidenceRequest fromBase64(String base64) throws JsonProcessingException {
        if (base64 == null) {
            return null;
        }
        var decodedBytes = Base64.getDecoder().decode(base64);
        var jsonString = new String(decodedBytes);
        return objectMapper.readValue(jsonString, EvidenceRequest.class);
    }
}
