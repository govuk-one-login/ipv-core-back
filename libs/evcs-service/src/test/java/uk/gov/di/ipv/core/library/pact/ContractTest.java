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
    private static final String EVCS_API_KEY = "test-evcs-api-key"; // pragma: allowlist secret
    private static final String TEST_EVCS_ACCESS_TOKEN = "test-acess-token";
    private static final String TEST_USER_ID = "test-user-id";
    private static final String INVALID_USER_ID = "invalid-user-id";
    private static final String VC_SIGNATURE =
            "LQy-7Yzes0HwH2ezhvoAahhxQCPjOSwRSl_yFe9KZlbXnKHDnHRY7lJZ_selbn5ZPxtlyECWTMIR_bKcmx3Whg"; // pragma: allowlist secret
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

    private static final List<EvcsCreateUserVCsDto> INVALID_CREATE_USER_VCS_DTO =
            List.of(
                    new EvcsCreateUserVCsDto(
                            VcFixtures.VC_ADDRESS.getVcString(), EvcsVCState.CURRENT, null, null));

    private static final List<EvcsUpdateUserVCsDto> EVCS_UPDATE_USER_VCS_DTO =
            List.of(
                    new EvcsUpdateUserVCsDto(
                            VC_SIGNATURE,
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

    @Pact(provider = "EvcsProvider", consumer = "IpvCoreBack")
    public RequestResponsePact validRetrieveVcRequestReturnsUsersVcWith200(
            PactDslWithProvider builder) {
        return builder.given("test-evcs-api-key is a valid API key")
                .given("test-acess-token is a valid access token")
                .given("test-user-id has one PENDING_RETURN VC")
                .uponReceiving("A request to get users VCS")
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
                                                    vc.stringType(
                                                            "vc",
                                                            VcFixtures.DCMAW_PASSPORT_VC
                                                                    .getVcString());
                                                    vc.stringType("state", "PENDING_RETURN");
                                                    vc.object("metadata", metadata -> {});
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

    @Pact(provider = "EvcsProvider", consumer = "IpvCoreBack")
    public RequestResponsePact validRetrieveVcRequestReturnsWith404(PactDslWithProvider builder) {
        return builder.given("test-evcs-api-key is a valid API key")
                .given("test-acess-token is a valid access token")
                .given("test-user-id has no PENDING_RETURN VC")
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
                .status(404)
                .toPact();
    }

    @Test
    @PactTestFor(pactMethod = "validRetrieveVcRequestReturnsWith404")
    void testRetrieveVcRequestReturns404(MockServer mockServer) throws Exception {
        // Under Test
        EvcsClient evcsClient = new EvcsClient(mockConfigService);
        var userVcs =
                evcsClient.getUserVcs(TEST_USER_ID, TEST_EVCS_ACCESS_TOKEN, VC_STATES_FOR_QUERY);
        assertEquals(Collections.emptyList(), userVcs.vcs());
    }

    @Pact(provider = "EvcsProvider", consumer = "IpvCoreBack")
    public RequestResponsePact invalidApiKeyReturns401(PactDslWithProvider builder) {
        return builder.given("invalid-api-key is an invalid API key")
                .given("test-acess-token is a valid access token")
                .given("test-user-id has no PENDING_RETURN VC")
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
    @PactTestFor(pactMethod = "invalidApiKeyReturns401")
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

    @Pact(provider = "EvcsProvider", consumer = "IpvCoreBack")
    public RequestResponsePact invalidAuthorizationTokenReturns403(PactDslWithProvider builder) {
        return builder.given("test-evcs-api-key is a valid API key")
                .given("invalid-access-token is an invalid access token")
                .given("test-user-id has no PENDING_RETURN VC")
                .uponReceiving("A request to get VCS")
                .path("/vcs/" + INVALID_USER_ID)
                .query("state=" + PENDING_RETURN)
                .method("GET")
                .headers(
                        Map.of(
                                "x-api-key",
                                EVCS_API_KEY,
                                "Authorization",
                                "Bearer " + "invalid-access-token"))
                .willRespondWith()
                .status(403)
                .toPact();
    }

    @Test
    @PactTestFor(pactMethod = "invalidAuthorizationTokenReturns403")
    void testRetrieveVcRequestReturns403(MockServer mockServer) {
        // Mock Data
        lenient()
                .when(mockConfigService.getSecret(ConfigurationVariable.EVCS_API_KEY))
                .thenReturn(EVCS_API_KEY);

        // Under Test
        EvcsClient evcsClient = new EvcsClient(mockConfigService);
        assertThrows(
                EvcsServiceException.class,
                () -> {
                    evcsClient.getUserVcs(
                            INVALID_USER_ID, "invalid-access-token", VC_STATES_FOR_QUERY);
                });
    }

    @Pact(provider = "EvcsProvider", consumer = "IpvCoreBack")
    public RequestResponsePact validCreateUserVcReturnsMessageIdWith202(
            PactDslWithProvider builder) {
        return builder.given("test-evcs-api-key is a valid API key")
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
                .status(202)
                .toPact();
    }

    private DslPart getRequestBodyForUserVC() {
        return newJsonArray(
                        array -> {
                            array.object(
                                    vcObject -> {
                                        vcObject.stringType(
                                                "vc", VcFixtures.DCMAW_PASSPORT_VC.getVcString());
                                        vcObject.stringType("state", "CURRENT");
                                        vcObject.object(
                                                "metadata",
                                                metadata -> {
                                                    metadata.stringType("reason", "testing");
                                                    metadata.stringType(
                                                            "timestampMs", "1711721297123");
                                                    metadata.stringType(
                                                            "txmaEventId", "txma-testing-event-id");
                                                });
                                        vcObject.stringType("provenance", "ONLINE");
                                    });
                        })
                .build();
    }

    @Test
    @PactTestFor(pactMethod = "validCreateUserVcReturnsMessageIdWith202")
    void testCreateVcRequestReturnsUsersVcWith202(MockServer mockServer) throws Exception {
        // Under Test
        EvcsClient evcsClient = new EvcsClient(mockConfigService);
        try {
            evcsClient.storeUserVCs(TEST_USER_ID, EVCS_CREATE_USER_VCS_DTO);
        } catch (EvcsServiceException e) {
            fail("EvcsServiceException was thrown");
        }
    }

    @Pact(provider = "EvcsProvider", consumer = "IpvCoreBack")
    public RequestResponsePact invalidCreateUserVcReturns400(PactDslWithProvider builder) {
        return builder.uponReceiving("A request to create EVCS user VCs")
                .path("/vcs/" + TEST_USER_ID)
                .method("POST")
                .headers(Map.of(CONTENT_TYPE, ContentType.APPLICATION_JSON.toString()))
                .body(invalidRequestBodyForUserVC())
                .willRespondWith()
                .status(400)
                .toPact();
    }

    private DslPart invalidRequestBodyForUserVC() {
        return newJsonArray(
                        array -> {
                            array.object(
                                    vcObject -> {
                                        vcObject.stringType("vc", "invalid-vc-string");
                                        vcObject.stringType("state", "CURRENT");
                                    });
                        })
                .build();
    }

    @Test
    @PactTestFor(pactMethod = "invalidCreateUserVcReturns400")
    void testCreateUserVcRequestReturns400(MockServer mockServer) {
        // Under Test
        EvcsClient evcsClient = new EvcsClient(mockConfigService);
        assertThrows(
                EvcsServiceException.class,
                () -> {
                    evcsClient.storeUserVCs(TEST_USER_ID, INVALID_CREATE_USER_VCS_DTO);
                });
    }

    @Pact(provider = "EvcsProvider", consumer = "IpvCoreBack")
    public RequestResponsePact createUserVcForExistingVcReturns409(PactDslWithProvider builder) {
        return builder.given("User already has VC in EVCS")
                .given("test-evcs-api-key is a valid API key")
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
                .status(409)
                .toPact();
    }

    @Test
    @PactTestFor(pactMethod = "createUserVcForExistingVcReturns409")
    void testCreateUserVcRequestReturns409(MockServer mockServer) {
        // Under Test
        EvcsClient evcsClient = new EvcsClient(mockConfigService);
        assertThrows(
                EvcsServiceException.class,
                () -> {
                    evcsClient.storeUserVCs(TEST_USER_ID, EVCS_CREATE_USER_VCS_DTO);
                });
    }

    @Pact(provider = "EvcsProvider", consumer = "IpvCoreBack")
    public RequestResponsePact validUpdateUserVcReturnsMessageIdWith204(
            PactDslWithProvider builder) {
        return builder.given("User has a valid VC")
                .given("test-evcs-api-key is a valid API key")
                .uponReceiving("A request to update EVCS user VCs")
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
                                        vcObject.stringType("signature", VC_SIGNATURE);
                                        vcObject.stringType("state", "CURRENT");
                                        vcObject.object(
                                                "metadata",
                                                metadata -> {
                                                    metadata.stringType("reason", "testing");
                                                    metadata.stringType(
                                                            "timestampMs", "1711721297123");
                                                    metadata.stringType(
                                                            "txmaEventId", "txma-testing-event-id");
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

    @Pact(provider = "EvcsProvider", consumer = "IpvCoreBack")
    public RequestResponsePact invalidUpdateUserVcReturns400(PactDslWithProvider builder) {
        return builder.given("EVCS client exist")
                .given("User has a valid VC")
                .uponReceiving("A request to create EVCS user VCs")
                .path("/vcs/" + INVALID_USER_ID)
                .method("PATCH")
                .headers(Map.of(CONTENT_TYPE, ContentType.APPLICATION_JSON.toString()))
                .body(getRequestBodyUpdateVC())
                .willRespondWith()
                .status(400)
                .toPact();
    }

    @Test
    @PactTestFor(pactMethod = "invalidUpdateUserVcReturns400")
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
