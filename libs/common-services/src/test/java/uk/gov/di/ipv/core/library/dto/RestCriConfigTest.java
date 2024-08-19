package uk.gov.di.ipv.core.library.dto;

import com.fasterxml.jackson.databind.ObjectMapper;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertEquals;

class RestCriConfigTest {
    private static final ObjectMapper OBJECT_MAPPER = new ObjectMapper();

    @Test
    void getRequestTimeoutShouldReturnDefaultIfNotSet() throws Exception {
        var jsonConfigWithNoTimeout =
                "{\"credentialUrl\":\"http://example.com\",\"requiresApiKey\":\"false\"}";
        var config = OBJECT_MAPPER.readValue(jsonConfigWithNoTimeout, RestCriConfig.class);

        assertEquals(30, config.getRequestTimeout());
    }

    @Test
    void getRequestTimeoutShouldReturnDefinedValue() throws Exception {
        var jsonConfigWithTimeout =
                "{\"credentialUrl\":\"http://example.com\",\"requiresApiKey\":\"false\",\"requestTimeout\":5}";
        var config = OBJECT_MAPPER.readValue(jsonConfigWithTimeout, RestCriConfig.class);

        assertEquals(5, config.getRequestTimeout());
    }
}
