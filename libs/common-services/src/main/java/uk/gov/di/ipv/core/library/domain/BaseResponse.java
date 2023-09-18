package uk.gov.di.ipv.core.library.domain;

import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.ObjectMapper;
import uk.gov.di.ipv.core.library.annotations.ExcludeFromGeneratedCoverageReport;

import java.util.Map;

@ExcludeFromGeneratedCoverageReport
public abstract class BaseResponse {
    protected static final ObjectMapper objectMapper = new ObjectMapper();

    public Map<String, Object> toObjectMap() {
        return objectMapper.convertValue(this, new TypeReference<>() {});
    }
}
