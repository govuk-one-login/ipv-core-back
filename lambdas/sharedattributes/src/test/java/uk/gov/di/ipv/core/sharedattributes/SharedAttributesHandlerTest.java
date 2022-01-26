package uk.gov.di.ipv.core.sharedattributes;

import com.amazonaws.services.lambda.runtime.Context;
import com.amazonaws.services.lambda.runtime.events.APIGatewayProxyRequestEvent;
import com.amazonaws.services.lambda.runtime.events.APIGatewayProxyResponseEvent;
import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import uk.gov.di.ipv.core.library.service.UserIdentityService;

import java.util.Collections;
import java.util.List;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.junit.jupiter.api.Assertions.fail;
import static org.mockito.Mockito.when;

@ExtendWith(MockitoExtension.class)
class SharedAttributesHandlerTest {

    public static final String SESSION_ID = "the-session-id";
    public static final Map<String, Object> CREDENTIAL_INPUT_1 =
            Map.of(
                    "attributes",
                    Map.of(
                            "names",
                            Map.of("givenNames", List.of("John", "H"), "familyName", "Watson"),
                            "dateOfBirth",
                            "2021-03-01",
                            "address",
                            Map.of(
                                    "line1", "Current 123 Street",
                                    "postcode", "Current M34 1AA"),
                            "addressHistory",
                            List.of(
                                    Map.of(
                                            "line1", "Previous 123 Street",
                                            "postcode", "Previous M34 1AA"),
                                    Map.of(
                                            "line1", "Old 321 Street",
                                            "postcode", "Old M34 1AA"))));

    public static final Map<String, Object> CREDENTIAL_INPUT_2 =
            Map.of(
                    "attributes",
                    Map.of(
                            "names",
                            Map.of("givenNames", List.of("Sherlock"), "familyName", "Holmes"),
                            "dateOfBirth",
                            "1991-03-01",
                            "address",
                            Map.of(
                                    "line1", "321 Street",
                                    "postcode", "321 Street")));

    private final ObjectMapper objectMapper = new ObjectMapper();
    @Mock private Context context;
    @Mock private UserIdentityService userIdentityService;
    private SharedAttributesHandler underTest;

    @BeforeEach
    void setUp() {
        underTest = new SharedAttributesHandler(userIdentityService);
    }

    @Test
    void shouldExtractSessionIdFromHeaderAndReturnSharedAttributesAndStatusOK()
            throws JsonProcessingException {

        when(userIdentityService.getUserIssuedCredentials(SESSION_ID))
                .thenReturn(
                        Map.of(
                                "CredentialIssuer1",
                                objectMapper.writeValueAsString(CREDENTIAL_INPUT_1),
                                "CredentialIssuer2",
                                objectMapper.writeValueAsString(CREDENTIAL_INPUT_2)));

        APIGatewayProxyRequestEvent input = new APIGatewayProxyRequestEvent();
        input.setHeaders(Map.of("ipv-session-id", SESSION_ID));

        APIGatewayProxyResponseEvent response = underTest.handleRequest(input, context);

        JsonNode body = objectMapper.readTree(response.getBody());

        assertEquals(200, response.getStatusCode());
        assertEquals(2, body.get("names").size());

        body.get("names")
                .forEach(
                        (name) -> {
                            if (name.get("familyName").asText().equals("Holmes")) {
                                assertEquals(
                                        "[ \"Sherlock\" ]",
                                        name.get("givenNames").toPrettyString());
                            } else if (name.get("familyName").asText().equals("Watson")) {
                                assertEquals(
                                        "[ \"John\", \"H\" ]",
                                        name.get("givenNames").toPrettyString());
                            } else {
                                fail("Unexpected familyName");
                            }
                        });

        assertEquals("2021-03-01", body.get("dateOfBirths").get(0).asText());
        assertTrue(body.get("addresses").toPrettyString().contains("123 Street"));
        assertEquals(2, body.get("addresses").size());
        assertEquals(2, body.get("addressHistory").size());
    }

    @Test
    void shouldReturnOKIfZeroCredentialExists() {
        when(userIdentityService.getUserIssuedCredentials(SESSION_ID))
                .thenReturn(Collections.emptyMap());

        APIGatewayProxyRequestEvent input = new APIGatewayProxyRequestEvent();
        input.setHeaders(Map.of("ipv-session-id", SESSION_ID));

        APIGatewayProxyResponseEvent response = underTest.handleRequest(input, context);
        assertEquals(200, response.getStatusCode());
    }

    @Test
    void shouldReturnBadRequestIfSessionIdIsNotInTheHeader() throws JsonProcessingException {
        APIGatewayProxyRequestEvent input = new APIGatewayProxyRequestEvent();
        input.setHeaders(Map.of("not-ipv-session-header", "dummy-value"));

        APIGatewayProxyResponseEvent response = underTest.handleRequest(input, context);
        assertEquals(400, response.getStatusCode());

        Map<String, Object> responseBody = objectMapper.readValue(response.getBody(), Map.class);
        assertEquals(1010, responseBody.get("code"));
        assertEquals("Missing ipv session id header", responseBody.get("message"));
    }
}
