package uk.gov.di.ipv.core.library.domain;

import com.fasterxml.jackson.annotation.JsonSubTypes;
import com.fasterxml.jackson.annotation.JsonTypeInfo;
import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.ObjectMapper;
import uk.gov.di.ipv.core.library.domain.buildclientoauthresponse.ClientResponse;

import java.util.Map;

import static com.fasterxml.jackson.annotation.JsonTypeInfo.As.PROPERTY;
import static com.fasterxml.jackson.annotation.JsonTypeInfo.Id.NAME;

@JsonTypeInfo(use = NAME, include = PROPERTY)
@JsonSubTypes({@JsonSubTypes.Type(value = ClientResponse.class, name = "client")})
public interface BaseResponse {
    default Map<String, Object> toMap() {
        ObjectMapper objectMapper = new ObjectMapper();
        return objectMapper.convertValue(this, new TypeReference<Map<String, Object>>() {});
    }
}
