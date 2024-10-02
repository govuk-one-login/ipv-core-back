package uk.gov.di.ipv.core.library.pact;

import au.com.dius.pact.consumer.MockServer;
import au.com.dius.pact.consumer.dsl.DslPart;
import au.com.dius.pact.consumer.dsl.PactDslWithProvider;
import au.com.dius.pact.consumer.junit.MockServerConfig;
import au.com.dius.pact.consumer.junit5.PactConsumerTestExt;
import au.com.dius.pact.consumer.junit5.PactTestFor;
import au.com.dius.pact.core.model.RequestResponsePact;
import au.com.dius.pact.core.model.annotations.Pact;
import org.apache.http.entity.ContentType;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import uk.gov.di.ipv.core.library.client.EvcsClient;
import uk.gov.di.ipv.core.library.config.ConfigurationVariable;
import uk.gov.di.ipv.core.library.dto.EvcsCreateUserVCsDto;
import uk.gov.di.ipv.core.library.dto.EvcsUpdateUserVCsDto;
import uk.gov.di.ipv.core.library.enums.EvcsVCState;
import uk.gov.di.ipv.core.library.exception.EvcsServiceException;
import uk.gov.di.ipv.core.library.fixtures.VcFixtures;
import uk.gov.di.ipv.core.library.service.ConfigService;

import java.util.Collections;
import java.util.List;
import java.util.Map;

import static au.com.dius.pact.consumer.dsl.LambdaDsl.newJsonArray;
import static au.com.dius.pact.consumer.dsl.LambdaDsl.newJsonBody;
import static org.apache.http.HttpHeaders.CONTENT_TYPE;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.fail;
import static org.mockito.Mockito.lenient;
import static org.mockito.Mockito.when;
import static uk.gov.di.ipv.core.library.enums.EvcsVCState.PENDING_RETURN;
import static uk.gov.di.ipv.core.library.enums.EvcsVcProvenance.ONLINE;

@ExtendWith(PactConsumerTestExt.class)
@ExtendWith(MockitoExtension.class)
@PactTestFor(providerName = "EvcsProvider")
@MockServerConfig(hostInterface = "localhost")
class ContractTest {
    private static final String EVCS_API_KEY =
            "L2BGccX59Ea9PMJ3ipu9t7r99ykD2Tlh1KYpdjdg"; // pragma: allowlist secret
    private static final String TEST_EVCS_ACCESS_TOKEN = "TEST_EVCS_ACCESS_TOKEN";
    private static final String TEST_USER_ID = "9bd7f130-4238-4532-83cd-01cb29584834";
    private static final String INVALID_USER_ID = "invalid-user-id";
    private static final List<EvcsVCState> VC_STATES_FOR_QUERY = List.of(PENDING_RETURN);

    private static final List<EvcsCreateUserVCsDto> EVCS_CREATE_USER_VCS_DTO =
            List.of(
                    new EvcsCreateUserVCsDto(
                            VcFixtures.VC_ADDRESS.getVcString(),
                            EvcsVCState.CURRENT,
                            Map.of(
                                    "reason", "testing",
                                    "txmaEventId", "txma-event-id-2",
                                    "timestampMs", "1714478033959"),
                            ONLINE));

    private static final List<EvcsUpdateUserVCsDto> EVCS_UPDATE_USER_VCS_DTO =
            List.of(
                    new EvcsUpdateUserVCsDto(
                            "VC_Signature1",
                            EvcsVCState.HISTORIC,
                            Map.of(
                                    "reason", "testing",
                                    "txmaEventId", "txma-event-id-2",
                                    "timestampMs", "1714478033959")));

    @Mock ConfigService mockConfigService;

    @BeforeEach
    void setUp(MockServer mockServer) {
        when(mockConfigService.getParameter(ConfigurationVariable.EVCS_APPLICATION_URL))
                .thenReturn("http://localhost:" + mockServer.getPort());
        lenient()
                .when(mockConfigService.getSecret(ConfigurationVariable.EVCS_API_KEY))
                .thenReturn(EVCS_API_KEY);
    }

    @Pact(provider = "EvcsProvider", consumer = "EvcsConsumer")
    public RequestResponsePact validRetrieveVcRequestReturnsUsersVcWith200(
            PactDslWithProvider builder) {
        return builder.given("EVCS client exist")
                .given("VCS exist")
                .given("EVC has users VC")
                .uponReceiving("A request to get VCS")
                .path("/vcs/" + TEST_USER_ID)
                .query("state=" + PENDING_RETURN)
                .method("GET")
                .headers(
                        Map.of(
                                "x-api-key",
                                EVCS_API_KEY,
                                "Authorization",
                                "Bearer " + TEST_EVCS_ACCESS_TOKEN))
                .willRespondWith()
                .status(200)
                .body(getResponseBodyForUserVC())
                .toPact();
    }

    private DslPart getResponseBodyForUserVC() {
        return newJsonBody(
                        body -> {
                            body.array(
                                    "vcs",
                                    vcs -> {
                                        vcs.object(
                                                vc -> {
                                                    vc.stringType("vc", "vc");
                                                    vc.stringType("state", "ABANDONED");
                                                    vc.object(
                                                            "metadata",
                                                            metadata -> {
                                                                metadata.stringType(
                                                                        "reason",
                                                                        "abandoned due inactivity");
                                                                metadata.numberType(
                                                                        "timestampMs",
                                                                        1711721297123L);
                                                                metadata.stringType(
                                                                        "txmaEventId",
                                                                        "1a116fe7-2ff9-4f7c-940d-d55fa7d03d66");
                                                            });
                                                });
                                    });
                        })
                .build();
    }

    @Test
    @PactTestFor(pactMethod = "validRetrieveVcRequestReturnsUsersVcWith200")
    void testRetrieveVcRequestReturnsUsersVcWith200(MockServer mockServer) throws Exception {
        // Under Test
        EvcsClient evcsClient = new EvcsClient(mockConfigService);
        var evcsGetUserVCsDto =
                evcsClient.getUserVcs(TEST_USER_ID, TEST_EVCS_ACCESS_TOKEN, VC_STATES_FOR_QUERY);

        // Assertions
        assertEquals(1, evcsGetUserVCsDto.vcs().size());
    }

    @Pact(provider = "EvcsProvider", consumer = "EvcsConsumer")
    public RequestResponsePact invalidRetrieveVcRequestReturnsWith400(PactDslWithProvider builder) {
        return builder.given("EVCS client exist")
                .given("VCS exist")
                .given("EVC has users VC")
                .uponReceiving("A request to get VCS")
                .path("/vcs/" + INVALID_USER_ID)
                .query("state=" + PENDING_RETURN)
                .method("GET")
                .headers(
                        Map.of(
                                "x-api-key",
                                EVCS_API_KEY,
                                "Authorization",
                                "Bearer " + TEST_EVCS_ACCESS_TOKEN))
                .willRespondWith()
                .status(400)
                .toPact();
    }

    @Test
    @PactTestFor(pactMethod = "invalidRetrieveVcRequestReturnsWith400")
    void testRetrieveVcRequestReturns400(MockServer mockServer) {
        // Under Test
        EvcsClient evcsClient = new EvcsClient(mockConfigService);
        assertThrows(
                EvcsServiceException.class,
                () -> {
                    evcsClient.getUserVcs(
                            INVALID_USER_ID, TEST_EVCS_ACCESS_TOKEN, VC_STATES_FOR_QUERY);
                });
    }

    @Pact(provider = "EvcsProvider", consumer = "EvcsConsumer")
    public RequestResponsePact invalidRetrieveVcRequestReturnsWith404(PactDslWithProvider builder) {
        return builder.given("EVCS client exist")
                .given("VCS exist")
                .given("EVC has users VC")
                .uponReceiving("A request to get VCS")
                .path("/vcs/" + INVALID_USER_ID)
                .query("state=" + PENDING_RETURN)
                .method("GET")
                .headers(
                        Map.of(
                                "x-api-key",
                                EVCS_API_KEY,
                                "Authorization",
                                "Bearer " + TEST_EVCS_ACCESS_TOKEN))
                .willRespondWith()
                .status(404)
                .toPact();
    }

    @Test
    @PactTestFor(pactMethod = "invalidRetrieveVcRequestReturnsWith404")
    void testRetrieveVcRequestReturns404(MockServer mockServer) throws Exception {
        // Under Test
        EvcsClient evcsClient = new EvcsClient(mockConfigService);
        var userVcs =
                evcsClient.getUserVcs(INVALID_USER_ID, TEST_EVCS_ACCESS_TOKEN, VC_STATES_FOR_QUERY);
        assertEquals(Collections.emptyList(), userVcs.vcs());
    }

    @Pact(provider = "EvcsProvider", consumer = "EvcsConsumer")
    public RequestResponsePact invalidRetrieveVcRequestReturnsWith401(PactDslWithProvider builder) {
        return builder.given("EVCS client exist")
                .given("VCS exist")
                .given("EVC has users VC")
                .uponReceiving("A request to get VCS")
                .path("/vcs/" + INVALID_USER_ID)
                .query("state=" + PENDING_RETURN)
                .method("GET")
                .headers(
                        Map.of(
                                "x-api-key",
                                "invalid-api-key",
                                "Authorization",
                                "Bearer " + TEST_EVCS_ACCESS_TOKEN))
                .willRespondWith()
                .status(401)
                .toPact();
    }

    @Test
    @PactTestFor(pactMethod = "invalidRetrieveVcRequestReturnsWith401")
    void testRetrieveVcRequestReturns401(MockServer mockServer) {
        // Mock Data
        lenient()
                .when(mockConfigService.getSecret(ConfigurationVariable.EVCS_API_KEY))
                .thenReturn("invalid-api-key");

        // Under Test
        EvcsClient evcsClient = new EvcsClient(mockConfigService);
        assertThrows(
                EvcsServiceException.class,
                () -> {
                    evcsClient.getUserVcs(
                            INVALID_USER_ID, TEST_EVCS_ACCESS_TOKEN, VC_STATES_FOR_QUERY);
                });
    }

    @Pact(provider = "EvcsProvider", consumer = "EvcsConsumer")
    public RequestResponsePact validCreateUserVcReturnsMessageIdWith200(
            PactDslWithProvider builder) {
        return builder.given("EVCS client exist")
                .given("User has a valid VC")
                .uponReceiving("A request to create EVCS user VCs")
                .path("/vcs/" + TEST_USER_ID)
                .method("POST")
                .headers(
                        Map.of(
                                "x-api-key",
                                EVCS_API_KEY,
                                CONTENT_TYPE,
                                ContentType.APPLICATION_JSON.toString()))
                .body(getRequestBodyForUserVC())
                .willRespondWith()
                .status(200)
                .body(getResponseBodyCreateUserVC())
                .toPact();
    }

    private DslPart getRequestBodyForUserVC() {
        return newJsonArray(
                        array -> {
                            array.object(
                                    vcObject -> {
                                        vcObject.stringType("vc", "vc");
                                        vcObject.stringType("state", "CURRENT");
                                        vcObject.object(
                                                "metadata",
                                                metadata -> {
                                                    metadata.stringType("reason", "ABANDON");
                                                    metadata.stringType(
                                                            "timestampMs", "1711721297123");
                                                    metadata.stringType(
                                                            "txmaEventId",
                                                            "1a116fe7-2ff9-4f7c-940d-d55fa7d03d66");
                                                });
                                        vcObject.stringType("provenance", "ONLINE");
                                    });
                        })
                .build();
    }

    private DslPart getResponseBodyCreateUserVC() {
        return newJsonBody(
                        body -> {
                            body.stringType("messageId", "bd8359d9-d559-47dd-9467-2a31e88a9e2d");
                        })
                .build();
    }

    @Test
    @PactTestFor(pactMethod = "validCreateUserVcReturnsMessageIdWith200")
    void testCreateVcRequestReturnsUsersVcWith200(MockServer mockServer) throws Exception {
        // Under Test
        EvcsClient evcsClient = new EvcsClient(mockConfigService);
        try {
            evcsClient.storeUserVCs(TEST_USER_ID, EVCS_CREATE_USER_VCS_DTO);
        } catch (EvcsServiceException e) {
            fail("EvcsServiceException was thrown");
        }
    }

    @Pact(provider = "EvcsProvider", consumer = "EvcsConsumer")
    public RequestResponsePact invalidCreateUserVcReturnsMessageIdWith400(
            PactDslWithProvider builder) {
        return builder.given("EVCS client exist")
                .given("User has a valid VC")
                .uponReceiving("A request to create EVCS user VCs")
                .path("/vcs/" + INVALID_USER_ID)
                .method("POST")
                .headers(
                        Map.of(
                                "x-api-key",
                                EVCS_API_KEY,
                                CONTENT_TYPE,
                                ContentType.APPLICATION_JSON.toString()))
                .body(getRequestBodyForUserVC())
                .willRespondWith()
                .status(400)
                .toPact();
    }

    @Test
    @PactTestFor(pactMethod = "invalidCreateUserVcReturnsMessageIdWith400")
    void testCreateUserVcRequestReturns400(MockServer mockServer) {
        // Under Test
        EvcsClient evcsClient = new EvcsClient(mockConfigService);
        assertThrows(
                EvcsServiceException.class,
                () -> {
                    evcsClient.storeUserVCs(INVALID_USER_ID, EVCS_CREATE_USER_VCS_DTO);
                });
    }

    @Pact(provider = "EvcsProvider", consumer = "EvcsConsumer")
    public RequestResponsePact validUpdateUserVcReturnsMessageIdWith204(
            PactDslWithProvider builder) {
        return builder.given("EVCS client exist")
                .given("User has a valid VC")
                .uponReceiving("A request to create EVCS user VCs")
                .path("/vcs/" + TEST_USER_ID)
                .method("PATCH")
                .headers(
                        Map.of(
                                "x-api-key",
                                EVCS_API_KEY,
                                CONTENT_TYPE,
                                ContentType.APPLICATION_JSON.toString()))
                .body(getRequestBodyUpdateVC())
                .willRespondWith()
                .status(204)
                .toPact();
    }

    private DslPart getRequestBodyUpdateVC() {
        return newJsonArray(
                        array -> {
                            array.object(
                                    vcObject -> {
                                        vcObject.stringType("signature", "signature");
                                        vcObject.stringType("state", "CURRENT");
                                        vcObject.object(
                                                "metadata",
                                                metadata -> {
                                                    metadata.stringType("reason", "ABANDON");
                                                    metadata.stringType(
                                                            "timestampMs", "1711721297123");
                                                    metadata.stringType(
                                                            "txmaEventId",
                                                            "1a116fe7-2ff9-4f7c-940d-d55fa7d03d66");
                                                });
                                    });
                        })
                .build();
    }

    @Test
    @PactTestFor(pactMethod = "validUpdateUserVcReturnsMessageIdWith204")
    void testUpdateVcRequestReturnsUsersVcWith204(MockServer mockServer) throws Exception {
        // Under Test
        EvcsClient evcsClient = new EvcsClient(mockConfigService);
        try {
            evcsClient.updateUserVCs(TEST_USER_ID, EVCS_UPDATE_USER_VCS_DTO);
        } catch (EvcsServiceException e) {
            fail("EvcsServiceException was thrown");
        }
    }

    @Pact(provider = "EvcsProvider", consumer = "EvcsConsumer")
    public RequestResponsePact invalidUpdateUserVcReturnsMessageIdWith400(
            PactDslWithProvider builder) {
        return builder.given("EVCS client exist")
                .given("User has a valid VC")
                .uponReceiving("A request to create EVCS user VCs")
                .path("/vcs/" + INVALID_USER_ID)
                .method("PATCH")
                .headers(
                        Map.of(
                                "x-api-key",
                                EVCS_API_KEY,
                                CONTENT_TYPE,
                                ContentType.APPLICATION_JSON.toString()))
                .body(getRequestBodyUpdateVC())
                .willRespondWith()
                .status(400)
                .toPact();
    }

    @Test
    @PactTestFor(pactMethod = "invalidUpdateUserVcReturnsMessageIdWith400")
    void testUpdateVcRequestReturns400(MockServer mockServer) {
        // Under Test
        EvcsClient evcsClient = new EvcsClient(mockConfigService);
        assertThrows(
                EvcsServiceException.class,
                () -> {
                    evcsClient.updateUserVCs(INVALID_USER_ID, EVCS_UPDATE_USER_VCS_DTO);
                });
    }
}
