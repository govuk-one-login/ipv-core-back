package uk.gov.di.ipv.core.library.evcs.pact;

import au.com.dius.pact.consumer.MockServer;
import au.com.dius.pact.consumer.dsl.DslPart;
import au.com.dius.pact.consumer.dsl.PactDslWithProvider;
import au.com.dius.pact.consumer.junit.MockServerConfig;
import au.com.dius.pact.consumer.junit5.PactConsumerTestExt;
import au.com.dius.pact.consumer.junit5.PactTestFor;
import au.com.dius.pact.core.model.RequestResponsePact;
import au.com.dius.pact.core.model.annotations.Pact;
import org.apache.hc.core5.http.ContentType;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import uk.gov.di.ipv.core.library.config.ConfigurationVariable;
import uk.gov.di.ipv.core.library.enums.Vot;
import uk.gov.di.ipv.core.library.evcs.client.EvcsClient;
import uk.gov.di.ipv.core.library.evcs.dto.EvcsCreateUserVCsDto;
import uk.gov.di.ipv.core.library.evcs.dto.EvcsPutUserVCsDto;
import uk.gov.di.ipv.core.library.evcs.dto.EvcsStoredIdentityDto;
import uk.gov.di.ipv.core.library.evcs.dto.EvcsUpdateUserVCsDto;
import uk.gov.di.ipv.core.library.evcs.enums.EvcsVCState;
import uk.gov.di.ipv.core.library.evcs.exception.EvcsServiceException;
import uk.gov.di.ipv.core.library.service.ConfigService;

import java.util.Collections;
import java.util.List;
import java.util.Map;

import static au.com.dius.pact.consumer.dsl.LambdaDsl.newJsonArray;
import static au.com.dius.pact.consumer.dsl.LambdaDsl.newJsonBody;
import static org.apache.hc.core5.http.HttpHeaders.CONTENT_TYPE;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.fail;
import static org.mockito.Mockito.lenient;
import static org.mockito.Mockito.when;
import static uk.gov.di.ipv.core.library.evcs.enums.EvcsVCState.PENDING_RETURN;
import static uk.gov.di.ipv.core.library.evcs.enums.EvcsVcProvenance.ONLINE;
import static uk.gov.di.ipv.core.library.fixtures.VcFixtures.vcAddressM1a;
import static uk.gov.di.ipv.core.library.fixtures.VcFixtures.vcDcmawPassport;
import static uk.gov.di.ipv.core.library.fixtures.VcFixtures.vcExperianFraudM1a;

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
    private static final String VC_STRING =
            "eyJ0eXAiOiJKV1QiLCJhbGciOiJFUzI1NiJ9.eyJpc3MiOiJodHRwczovL3Jldmlldy1wLnN0YWdpbmcuYWNjb3VudC5nb3YudWsiLCJzdWIiOiJ1cm46dXVpZDowMWE0NDM0Mi1lNjQzLTRjYTktODMwNi1hOGUwNDQwOTJmYjAiLCJuYmYiOjE3MDU5ODY1MjEsInZjIjp7InR5cGUiOlsiVmVyaWZpYWJsZUNyZWRlbnRpYWwiLCJJZGVudGl0eUNoZWNrQ3JlZGVudGlhbCJdLCJjcmVkZW50aWFsU3ViamVjdCI6eyJuYW1lIjpbeyJuYW1lUGFydHMiOlt7InR5cGUiOiJHaXZlbk5hbWUiLCJ2YWx1ZSI6Ik1PUkdBTiJ9LHsidHlwZSI6IkZhbWlseU5hbWUiLCJ2YWx1ZSI6IlNBUkFIIE1FUkVEWVRIIn1dfV0sImJpcnRoRGF0ZSI6W3sidmFsdWUiOiIxOTY1LTA3LTA4In1dLCJwYXNzcG9ydCI6W3siZG9jdW1lbnROdW1iZXIiOiIzMjE2NTQ5ODciLCJleHBpcnlEYXRlIjoiMjAzMC0wMS0wMSIsImljYW9Jc3N1ZXJDb2RlIjoiR0JSIn1dLCJhZGRyZXNzIjpbeyJhZGRyZXNzQ291bnRyeSI6IkdCIiwiYWRkcmVzc0xvY2FsaXR5IjoiR1JFQVQgTUlTU0VOREVOIiwiYnVpbGRpbmdOYW1lIjoiQ09ZIFBPTkQgQlVTSU5FU1MgUEFSSyIsImJ1aWxkaW5nTnVtYmVyIjoiMTYiLCJkZXBlbmRlbnRBZGRyZXNzTG9jYWxpdHkiOiJMT05HIEVBVE9OIiwiZGVwZW5kZW50U3RyZWV0TmFtZSI6IktJTkdTIFBBUksiLCJkb3VibGVEZXBlbmRlbnRBZGRyZXNzTG9jYWxpdHkiOiJTT01FIERJU1RSSUNUIiwib3JnYW5pc2F0aW9uTmFtZSI6IkZJTkNIIEdST1VQIiwicG9zdGFsQ29kZSI6IkhQMTYgMEFMIiwic3RyZWV0TmFtZSI6IkJJRyBTVFJFRVQiLCJzdWJCdWlsZGluZ05hbWUiOiJVTklUIDJCIiwidXBybiI6MTAwMTIwMDEyMDc3fV19LCJldmlkZW5jZSI6W3sidHlwZSI6IklkZW50aXR5Q2hlY2siLCJ0eG4iOiJiY2QyMzQ2Iiwic3RyZW5ndGhTY29yZSI6NCwidmFsaWRpdHlTY29yZSI6MiwidmVyaWZpY2F0aW9uU2NvcmUiOjMsImNpIjpbXSwiY2hlY2tEZXRhaWxzIjpbeyJjaGVja01ldGhvZCI6ImRhdGEiLCJkYXRhQ2hlY2siOiJjYW5jZWxsZWRfY2hlY2sifSx7ImNoZWNrTWV0aG9kIjoiZGF0YSIsImRhdGFDaGVjayI6InJlY29yZF9jaGVjayJ9XX1dfX0." // pragma: allowlist secret
                    + VC_SIGNATURE;
    private static final String SI_STRING = "";

    private static final List<EvcsVCState> VC_STATES_FOR_QUERY = List.of(PENDING_RETURN);

    private static final List<EvcsCreateUserVCsDto> EVCS_CREATE_USER_VCS_DTO =
            List.of(
                    new EvcsCreateUserVCsDto(
                            VC_STRING,
                            EvcsVCState.CURRENT,
                            Map.of(
                                    "reason", "testing",
                                    "txmaEventId", "txma-event-id-2",
                                    "timestampMs", "1714478033959"),
                            ONLINE));

    private static final List<EvcsCreateUserVCsDto> INVALID_CREATE_USER_VCS_DTO =
            List.of(new EvcsCreateUserVCsDto(VC_STRING, EvcsVCState.CURRENT, null, null));

    private static final EvcsPutUserVCsDto EVCS_PUT_P2_SI_AND_VCS_DTO =
            new EvcsPutUserVCsDto(
                    TEST_USER_ID,
                    List.of(
                            new EvcsCreateUserVCsDto(
                                    vcDcmawPassport()
                                            .getVcString(), EvcsVCState.CURRENT, Map.of(), ONLINE),
                            new EvcsCreateUserVCsDto(
                                    vcAddressM1a()
                                            .getVcString(), EvcsVCState.CURRENT, Map.of(), ONLINE),
                            new EvcsCreateUserVCsDto(
                                    vcExperianFraudM1a()
                                            .getVcString(), EvcsVCState.CURRENT, Map.of(), ONLINE)),
                    new EvcsStoredIdentityDto(SI_STRING, Vot.P2));

    private static final EvcsPutUserVCsDto DUPLICATE_CONFLICTING_VCS_DTO =
            new EvcsPutUserVCsDto(
                    TEST_USER_ID,
                    List.of(
                            new EvcsCreateUserVCsDto(
                                    VC_STRING, EvcsVCState.CURRENT, Map.of(), ONLINE),
                            new EvcsCreateUserVCsDto(
                                    VC_STRING, PENDING_RETURN, Map.of(), ONLINE)),
                    new EvcsStoredIdentityDto(SI_STRING, Vot.P2));

    private static final List<EvcsUpdateUserVCsDto> EVCS_POST_USER_VCS_DTO =
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
                                                    vc.stringType("vc", VC_STRING);
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
    public RequestResponsePact invalidApiKeyReturns403(PactDslWithProvider builder) {
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
                .status(403)
                .toPact();
    }

    @Test
    @PactTestFor(pactMethod = "invalidApiKeyReturns403")
    void testRetrieveVcRequestReturns403(MockServer mockServer) {
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
    public RequestResponsePact invalidAuthorizationTokenReturns401(PactDslWithProvider builder) {
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
                .status(401)
                .toPact();
    }

    @Test
    @PactTestFor(pactMethod = "invalidAuthorizationTokenReturns401")
    void testRetrieveVcRequestReturns401(MockServer mockServer) {
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
        return builder.given("Brand new user")
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
                .status(202)
                .toPact();
    }

    private DslPart getRequestBodyForUserVC() {
        return newJsonArray(
                        array -> {
                            array.object(
                                    vcObject -> {
                                        vcObject.stringType("vc", VC_STRING);
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
    void testCreateVcRequestReturnsUsersVcWith202(MockServer mockServer) {
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
                                        vcObject.stringType("state", "WRONG_STATE");
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
        return builder.given("Existing user")
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
                .given("test-user-id has one PENDING_RETURN VC")
                .uponReceiving("A request to update EVCS user VCs")
                .path("/vcs/" + TEST_USER_ID)
                .method("PATCH")
                .headers(
                        Map.of(
                                "x-api-key",
                                EVCS_API_KEY,
                                CONTENT_TYPE,
                                ContentType.APPLICATION_JSON.toString()))
                .body(getRequestBodyUpdateVC("CURRENT"))
                .willRespondWith()
                .status(204)
                .toPact();
    }

    private DslPart getRequestBodyUpdateVC(String state) {
        return newJsonArray(
                        array -> {
                            array.object(
                                    vcObject -> {
                                        vcObject.stringType("signature", VC_SIGNATURE);
                                        vcObject.stringType("state", state);
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
            evcsClient.updateUserVCs(TEST_USER_ID, EVCS_POST_USER_VCS_DTO);
        } catch (EvcsServiceException e) {
            fail("EvcsServiceException was thrown");
        }
    }

    @Pact(provider = "EvcsProvider", consumer = "IpvCoreBack")
    public RequestResponsePact invalidUpdateUserVcReturns400(PactDslWithProvider builder) {
        return builder.given("EVCS client exist")
                .given("test-evcs-api-key is a valid API key")
                .uponReceiving("A request to create EVCS user VCs")
                .path("/vcs/" + INVALID_USER_ID)
                .method("PATCH")
                .headers(
                        Map.of(
                                "x-api-key",
                                EVCS_API_KEY,
                                CONTENT_TYPE,
                                ContentType.APPLICATION_JSON.toString()))
                .body(getRequestBodyUpdateVC("INVALID_STATE"))
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
                    evcsClient.updateUserVCs(INVALID_USER_ID, EVCS_POST_USER_VCS_DTO);
                });
    }

    @Pact(provider = "EvcsProvider", consumer = "IpvCoreBack")
    public RequestResponsePact putVcsReturns202(PactDslWithProvider builder) {
        return builder.given(String.format("%s is a valid EVCS API key", EVCS_API_KEY))
                .uponReceiving("A request to put EVCS VCs and stored identity")
                .path("/vcs")
                .method("PUT")
                .headers(
                        Map.of(
                                "x-api-key",
                                EVCS_API_KEY,
                                CONTENT_TYPE,
                                ContentType.APPLICATION_JSON.toString()))
                .body(
                        newJsonBody(
                                        dto -> {
                                            dto.stringType("userId", TEST_USER_ID);
                                            dto.array(
                                                    "vcs", // M1A
                                                    vcDtos -> {
                                                        vcDtos.object(
                                                                vcDto -> {
                                                                    vcDto.stringType(
                                                                            "vc",
                                                                            vcDcmawPassport()
                                                                                    .getVcString());
                                                                    vcDto.stringType(
                                                                            "state",
                                                                            EvcsVCState.CURRENT
                                                                                    .toString());
                                                                    vcDto.object(
                                                                            "metadata", vc -> {});
                                                                    vcDto.stringType(
                                                                            "provenance",
                                                                            ONLINE.toString());
                                                                });
                                                        vcDtos.object(
                                                                vcDto -> {
                                                                    vcDto.stringType(
                                                                            "vc",
                                                                            vcAddressM1a()
                                                                                    .getVcString());
                                                                    vcDto.stringType(
                                                                            "state",
                                                                            EvcsVCState.CURRENT
                                                                                    .toString());
                                                                    vcDto.object(
                                                                            "metadata", vc -> {});
                                                                    vcDto.stringType(
                                                                            "provenance",
                                                                            ONLINE.toString());
                                                                });
                                                        vcDtos.object(
                                                                vcDto -> {
                                                                    vcDto.stringType(
                                                                            "vc",
                                                                            vcExperianFraudM1a()
                                                                                    .getVcString());
                                                                    vcDto.stringType(
                                                                            "state",
                                                                            EvcsVCState.CURRENT
                                                                                    .toString());
                                                                    vcDto.object(
                                                                            "metadata", vc -> {});
                                                                    vcDto.stringType(
                                                                            "provenance",
                                                                            ONLINE.toString());
                                                                });
                                                    });
                                            dto.object(
                                                    "si",
                                                    si -> {
                                                        si.stringType("jwt", SI_STRING);
                                                        si.stringType("vot", Vot.P2.toString());
                                                    });
                                        })
                                .build())
                .willRespondWith()
                .status(202)
                .toPact();
    }

    @Test
    @PactTestFor(pactMethod = "putVcsReturns202")
    void testPutVcsRequestReturns200(MockServer mockServer) throws EvcsServiceException {
        // Arrange
        var evcsClient = new EvcsClient(mockConfigService);

        // Act
        var response = evcsClient.storeUserVCs(EVCS_PUT_P2_SI_AND_VCS_DTO);

        // Assert
        assertEquals(202, response.statusCode());
    }

    @Pact(provider = "EvcsProvider", consumer = "IpvCoreBack")
    public RequestResponsePact putVcsReturns400(PactDslWithProvider builder) {
        return builder
                .given(String.format("%s is a valid EVCS API key", EVCS_API_KEY))
                .uponReceiving("A bad request with duplicate VCs with different states")
                .path("/vcs")
                .method("PUT")
                .headers(
                        Map.of(
                                "x-api-key", EVCS_API_KEY,
                                CONTENT_TYPE, ContentType.APPLICATION_JSON.toString()))
                .body(newJsonBody(dto -> {
                    dto.stringType("userId", TEST_USER_ID);
                    dto.array("vcs", vcs -> {
                        vcs.object(vc -> {
                            vc.stringType("vc", vcDcmawPassport().getVcString());
                            vc.stringType("state", EvcsVCState.CURRENT.toString());
                            vc.object("metadata", meta -> {});
                            vc.stringType("provenance", ONLINE.toString());
                        });
                        vcs.object(vc -> {
                            vc.stringType("vc", vcDcmawPassport().getVcString()); // same VC
                            vc.stringType("state", PENDING_RETURN.toString()); // conflicting state
                            vc.object("metadata", meta -> {});
                            vc.stringType("provenance", ONLINE.toString());
                        });
                    });
                }).build())
                .willRespondWith()
                .status(400)
                .body(newJsonBody(body -> {
                    body.stringType("error", "Duplicate VCs with conflicting state detected");
                }).build())
                .toPact();
    }

    @Test
    @PactTestFor(pactMethod = "putVcsReturns400")
    void testPutVcsReturns400(MockServer mockServer) {
        // Arrange
        var evcsClient = new EvcsClient(mockConfigService);

        // Act & Assert
        assertThrows(EvcsServiceException.class, () -> {
            evcsClient.storeUserVCs(DUPLICATE_CONFLICTING_VCS_DTO);
        });
    }

    @Pact(provider = "EvcsProvider", consumer = "IpvCoreBack")
    public RequestResponsePact putVcsReturns403(PactDslWithProvider builder) {
        return builder
                .given("Missing or invalid API key")
                .uponReceiving("A PUT request with missing or invalid API key")
                .path("/vcs")
                .method("PUT")
                .headers(Map.of(CONTENT_TYPE, ContentType.APPLICATION_JSON.toString()))
                .body(newJsonBody(dto -> {
                    dto.stringType("userId", TEST_USER_ID);
                    dto.array("vcs", vcs -> {
                        vcs.object(vc -> {
                            vc.stringType("vc", vcDcmawPassport().getVcString());
                            vc.stringType("state", EvcsVCState.CURRENT.toString());
                            vc.object("metadata", meta -> {});
                            vc.stringType("provenance", ONLINE.toString());
                        });
                    });
                }).build())
                .willRespondWith()
                .status(403)
                .toPact();
    }

    @Test
    @PactTestFor(pactMethod = "putVcsReturns403")
    void testPutVcsReturns403(MockServer mockServer) {
        // Arrange
        var evcsClient = new EvcsClient(mockConfigService);

        // Act & Assert
        assertThrows(EvcsServiceException.class, () -> {
            evcsClient.storeUserVCs(EVCS_PUT_P2_SI_AND_VCS_DTO);
        });
    }

    @Pact(provider = "EvcsProvider", consumer = "IpvCoreBack")
    public RequestResponsePact putVcsReturns415(PactDslWithProvider builder) {
        return builder
                .given("Request with unsupported Content-Type")
                .uponReceiving("A PUT request with invalid Content-Type")
                .path("/vcs")
                .method("PUT")
                .headers(Map.of(
                        "x-api-key", EVCS_API_KEY,
                        CONTENT_TYPE, "text/plain"))
                .body("some invalid body")
                .willRespondWith()
                .status(415)
                .toPact();
    }

    @Test
    @PactTestFor(pactMethod = "putVcsReturns415")
    void testPutVcsReturns415(MockServer mockServer) {
        // Arrange
        var evcsClient = new EvcsClient(mockConfigService);

        // Act & Assert
        assertThrows(EvcsServiceException.class, () -> {
            evcsClient.storeUserVCs(EVCS_PUT_P2_SI_AND_VCS_DTO);
        });
    }

    @Pact(provider = "EvcsProvider", consumer = "IpvCoreBack")
    public RequestResponsePact putVcsReturns409(PactDslWithProvider builder) {
        return builder.given("Existing user")
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
    @PactTestFor(pactMethod = "putVcsReturns409")
    void testPutVcsReturns409(MockServer mockServer) {
        // Arrange
        EvcsClient evcsClient = new EvcsClient(mockConfigService);

        // Act & Assert
        assertThrows(
                EvcsServiceException.class,
                () -> {
                    evcsClient.storeUserVCs(EVCS_PUT_P2_SI_AND_VCS_DTO);
                });
    }
}
