package uk.gov.di.ipv.core.library.evcs.pact;

import au.com.dius.pact.consumer.MockServer;
import au.com.dius.pact.consumer.dsl.DslPart;
import au.com.dius.pact.consumer.dsl.PactDslWithProvider;
import au.com.dius.pact.consumer.junit.MockServerConfig;
import au.com.dius.pact.consumer.junit5.PactConsumerTestExt;
import au.com.dius.pact.consumer.junit5.PactTestFor;
import au.com.dius.pact.core.model.RequestResponsePact;
import au.com.dius.pact.core.model.annotations.Pact;
import com.nimbusds.oauth2.sdk.http.HTTPResponse;
import org.apache.hc.core5.http.ContentType;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import uk.gov.di.ipv.core.library.config.ConfigurationVariable;
import uk.gov.di.ipv.core.library.domain.ErrorResponse;
import uk.gov.di.ipv.core.library.evcs.client.EvcsClient;
import uk.gov.di.ipv.core.library.evcs.dto.EvcsCreateUserVCsDto;
import uk.gov.di.ipv.core.library.evcs.dto.EvcsPostIdentityDto;
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
import static uk.gov.di.ipv.core.library.enums.Vot.P2;
import static uk.gov.di.ipv.core.library.evcs.enums.EvcsVCState.PENDING_RETURN;
import static uk.gov.di.ipv.core.library.evcs.enums.EvcsVcProvenance.ONLINE;

@ExtendWith(PactConsumerTestExt.class)
@ExtendWith(MockitoExtension.class)
@PactTestFor(providerName = "EvcsProvider")
@MockServerConfig(hostInterface = "localhost")
class ContractTest {
    private static final String EVCS_API_KEY = "test-evcs-api-key"; // pragma: allowlist secret
    private static final String EVCS_INVALID_API_KEY =
            "invalid-api-key"; // pragma: allowlist secret
    private static final String TEST_EVCS_ACCESS_TOKEN = "test-acess-token";
    private static final String TEST_USER_ID = "test-user-id";
    private static final String INVALID_USER_ID = "invalid-user-id";

    private static final String VC_SIGNATURE =
            "LQy-7Yzes0HwH2ezhvoAahhxQCPjOSwRSl_yFe9KZlbXnKHDnHRY7lJZ_selbn5ZPxtlyECWTMIR_bKcmx3Whg"; // pragma: allowlist secret
    private static final String VC_STRING =
            "eyJ0eXAiOiJKV1QiLCJhbGciOiJFUzI1NiJ9.eyJpc3MiOiJodHRwczovL3Jldmlldy1wLnN0YWdpbmcuYWNjb3VudC5nb3YudWsiLCJzdWIiOiJ1cm46dXVpZDowMWE0NDM0Mi1lNjQzLTRjYTktODMwNi1hOGUwNDQwOTJmYjAiLCJuYmYiOjE3MDU5ODY1MjEsInZjIjp7InR5cGUiOlsiVmVyaWZpYWJsZUNyZWRlbnRpYWwiLCJJZGVudGl0eUNoZWNrQ3JlZGVudGlhbCJdLCJjcmVkZW50aWFsU3ViamVjdCI6eyJuYW1lIjpbeyJuYW1lUGFydHMiOlt7InR5cGUiOiJHaXZlbk5hbWUiLCJ2YWx1ZSI6Ik1PUkdBTiJ9LHsidHlwZSI6IkZhbWlseU5hbWUiLCJ2YWx1ZSI6IlNBUkFIIE1FUkVEWVRIIn1dfV0sImJpcnRoRGF0ZSI6W3sidmFsdWUiOiIxOTY1LTA3LTA4In1dLCJwYXNzcG9ydCI6W3siZG9jdW1lbnROdW1iZXIiOiIzMjE2NTQ5ODciLCJleHBpcnlEYXRlIjoiMjAzMC0wMS0wMSIsImljYW9Jc3N1ZXJDb2RlIjoiR0JSIn1dLCJhZGRyZXNzIjpbeyJhZGRyZXNzQ291bnRyeSI6IkdCIiwiYWRkcmVzc0xvY2FsaXR5IjoiR1JFQVQgTUlTU0VOREVOIiwiYnVpbGRpbmdOYW1lIjoiQ09ZIFBPTkQgQlVTSU5FU1MgUEFSSyIsImJ1aWxkaW5nTnVtYmVyIjoiMTYiLCJkZXBlbmRlbnRBZGRyZXNzTG9jYWxpdHkiOiJMT05HIEVBVE9OIiwiZGVwZW5kZW50U3RyZWV0TmFtZSI6IktJTkdTIFBBUksiLCJkb3VibGVEZXBlbmRlbnRBZGRyZXNzTG9jYWxpdHkiOiJTT01FIERJU1RSSUNUIiwib3JnYW5pc2F0aW9uTmFtZSI6IkZJTkNIIEdST1VQIiwicG9zdGFsQ29kZSI6IkhQMTYgMEFMIiwic3RyZWV0TmFtZSI6IkJJRyBTVFJFRVQiLCJzdWJCdWlsZGluZ05hbWUiOiJVTklUIDJCIiwidXBybiI6MTAwMTIwMDEyMDc3fV19LCJldmlkZW5jZSI6W3sidHlwZSI6IklkZW50aXR5Q2hlY2siLCJ0eG4iOiJiY2QyMzQ2Iiwic3RyZW5ndGhTY29yZSI6NCwidmFsaWRpdHlTY29yZSI6MiwidmVyaWZpY2F0aW9uU2NvcmUiOjMsImNpIjpbXSwiY2hlY2tEZXRhaWxzIjpbeyJjaGVja01ldGhvZCI6ImRhdGEiLCJkYXRhQ2hlY2siOiJjYW5jZWxsZWRfY2hlY2sifSx7ImNoZWNrTWV0aG9kIjoiZGF0YSIsImRhdGFDaGVjayI6InJlY29yZF9jaGVjayJ9XX1dfX0." // pragma: allowlist secret
                    + VC_SIGNATURE;
    private static final String SI_JWT_STRING =
            "eyJ0eXAiOiJKV1QiLCJhbGciOiJFUzI1NiJ9.eyJpc3MiOiJodHRwczovL2lkZW50aXR5LmFjY291bnQuZ292LnVrIiwic3ViIjoidGVzdC11c2VyLWlkIiwiYXVkIjoiaHR0cHM6Ly9yZXVzZS1pZGVudGl0eS5hY2NvdW50Lmdvdi51ayIsIm5iZiI6MjY1ODgyOTcyMCwiaWF0IjoyNjU4ODI5NzIwLCJ2b3QiOiJQMiIsImNyZWRlbnRpYWxzIjpbImhqSmNtTEVFSWJHNkoxSWsydlc1b1JocGF6TDFTdnZ1dnlCZTVUNjJWdGxOaWs1enNLd1B0cWx5MGVEZUplaUNwNG94dGNtQmZHMUFQTU5SYXNiazhBIiwidEpyOGpveXNiUnpieVQwZThxUldUYXk4OGNORkZhOURBNVF5YzZySHZ3VXhsTVlkSVV6RG5WUVlmYjR4OE9fYmVVSGF4eG41TmlNQ3VhMnFkM3hGSHciLCJMRFk2aklQWHBIeEp1RFBrU1FsY1VzSE9MX3k0ajNaZEdMd2hLOHZDQWNlWFZodFIxWFBYbGpwZVc2YVVjajNROG03T3g1NUtCOUxlOVRQckY5eHIxUSJdLCJjbGFpbXMiOnt9fQ.omMIO4KF1uPKlWh252GIX21MgCfrH6qoQGezYcD_yZWDobZ5H0L3dCvQxEt7SVXLWmxtBsoQpv4Lf8kwfGVI2Q"; // pragma: allowlist secret

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

    private static final List<EvcsUpdateUserVCsDto> EVCS_UPDATE_USER_VCS_DTO =
            List.of(
                    new EvcsUpdateUserVCsDto(
                            VC_SIGNATURE,
                            EvcsVCState.HISTORIC,
                            Map.of(
                                    "reason", "testing",
                                    "txmaEventId", "txma-event-id-2",
                                    "timestampMs", "1714478033959")));
    private static final EvcsStoredIdentityDto EVCS_STORED_IDENTITY_DTO =
            new EvcsStoredIdentityDto(SI_JWT_STRING, P2);
    private static final EvcsStoredIdentityDto EVCS_INVALID_STORED_IDENTITY_DTO =
            new EvcsStoredIdentityDto(SI_JWT_STRING, null);

    @Mock ConfigService mockConfigService;

    @BeforeEach
    void setUp(MockServer mockServer) {
        when(mockConfigService.getParameter(ConfigurationVariable.EVCS_APPLICATION_URL))
                .thenReturn("http://localhost:" + mockServer.getPort());
        lenient()
                .when(mockConfigService.getSecret(ConfigurationVariable.EVCS_API_KEY))
                .thenReturn(EVCS_API_KEY);
    }

    // GET /vcs/{userId}
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
                                EVCS_INVALID_API_KEY,
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
                .thenReturn(EVCS_INVALID_API_KEY);

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

    // POST /vcs/{userId}
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

    // PATCH /vcs/{userId}
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
            evcsClient.updateUserVCs(TEST_USER_ID, EVCS_UPDATE_USER_VCS_DTO);
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
                    evcsClient.updateUserVCs(INVALID_USER_ID, EVCS_UPDATE_USER_VCS_DTO);
                });
    }

    // POST /identity
    @Pact(provider = "EvcsProvider", consumer = "IpvCoreBack")
    public RequestResponsePact postIdentityReturns202(PactDslWithProvider builder) {
        return builder.given("EVCS client exist")
                .given("test-evcs-api-key is a valid API key")
                .uponReceiving("A request to create a stored identity in EVCS.")
                .path("/identity")
                .method("POST")
                .headers(
                        Map.of(
                                "x-api-key",
                                EVCS_API_KEY,
                                CONTENT_TYPE,
                                ContentType.APPLICATION_JSON.toString()))
                .body(
                        newJsonBody(
                                        body -> {
                                            body.stringType("userId", TEST_USER_ID);
                                            body.object(
                                                    "si",
                                                    si -> {
                                                        si.stringType("jwt", SI_JWT_STRING);
                                                        si.stringType("vot", P2.toString());
                                                    });
                                        })
                                .build())
                .willRespondWith()
                .status(202)
                .toPact();
    }

    @Test
    @PactTestFor(pactMethod = "postIdentityReturns202")
    void testPostIdentityReturns202(MockServer mockServer) throws EvcsServiceException {
        // Arrange
        var evcsPostIdentityDto =
                new EvcsPostIdentityDto(TEST_USER_ID, null, EVCS_STORED_IDENTITY_DTO);
        var underTest = new EvcsClient(mockConfigService);

        // Act
        var response = underTest.storeUserIdentity(evcsPostIdentityDto);

        // Assert
        assertEquals(202, response.statusCode());
    }

    @Pact(provider = "EvcsProvider", consumer = "IpvCoreBack")
    public RequestResponsePact nullBodyPostIdentityReturns400(PactDslWithProvider builder) {
        return builder.given("EVCS client exist")
                .given("test-evcs-api-key is a valid API key")
                .uponReceiving("A request to create a stored identity in EVCS, with null user id")
                .path("/identity")
                .method("POST")
                .headers(
                        Map.of(
                                "x-api-key",
                                EVCS_API_KEY,
                                CONTENT_TYPE,
                                ContentType.APPLICATION_JSON.toString()))
                // Null body
                .willRespondWith()
                .status(400)
                .toPact();
    }

    @Test
    @PactTestFor(pactMethod = "nullBodyPostIdentityReturns400")
    void testNullBodyPostIdentityReturns400(MockServer mockServer) {
        // Arrange
        var underTest = new EvcsClient(mockConfigService);

        // Act & Assert
        var exception =
                assertThrows(
                        EvcsServiceException.class,
                        () -> {
                            underTest.storeUserIdentity(null);
                        });
        assertEquals(
                ErrorResponse.RECEIVED_NON_200_RESPONSE_STATUS_CODE, exception.getErrorResponse());
        assertEquals(HTTPResponse.SC_SERVER_ERROR, exception.getResponseCode());
    }

    @Pact(provider = "EvcsProvider", consumer = "IpvCoreBack")
    public RequestResponsePact nullUserIdPostIdentityReturns400(PactDslWithProvider builder) {
        return builder.given("EVCS client exist")
                .given("test-evcs-api-key is a valid API key")
                .uponReceiving("A request to create a stored identity in EVCS, with null user id")
                .path("/identity")
                .method("POST")
                .headers(
                        Map.of(
                                "x-api-key",
                                EVCS_API_KEY,
                                CONTENT_TYPE,
                                ContentType.APPLICATION_JSON.toString()))
                .body(
                        newJsonBody(
                                        body -> {
                                            // Null user id
                                            body.object(
                                                    "si",
                                                    si -> {
                                                        si.stringType("jwt", SI_JWT_STRING);
                                                        si.stringType("vot", P2.toString());
                                                    });
                                        })
                                .build())
                .willRespondWith()
                .status(400)
                .toPact();
    }

    @Test
    @PactTestFor(pactMethod = "nullUserIdPostIdentityReturns400")
    void testNullUserIdPostIdentityReturns400(MockServer mockServer) {
        // Arrange
        var evcsPostIdentityDto = new EvcsPostIdentityDto(null, null, EVCS_STORED_IDENTITY_DTO);
        var underTest = new EvcsClient(mockConfigService);

        // Act & Assert
        var exception =
                assertThrows(
                        EvcsServiceException.class,
                        () -> {
                            underTest.storeUserIdentity(evcsPostIdentityDto);
                        });
        assertEquals(
                ErrorResponse.RECEIVED_NON_200_RESPONSE_STATUS_CODE, exception.getErrorResponse());
        assertEquals(HTTPResponse.SC_SERVER_ERROR, exception.getResponseCode());
    }

    @Pact(provider = "EvcsProvider", consumer = "IpvCoreBack")
    public RequestResponsePact emptyUserIdPostIdentityReturns400(PactDslWithProvider builder) {
        return builder.given("EVCS client exist")
                .given("test-evcs-api-key is a valid API key")
                .uponReceiving("A request to create a stored identity in EVCS, with empty user id")
                .path("/identity")
                .method("POST")
                .headers(
                        Map.of(
                                "x-api-key",
                                EVCS_API_KEY,
                                CONTENT_TYPE,
                                ContentType.APPLICATION_JSON.toString()))
                .body(
                        newJsonBody(
                                        body -> {
                                            body.stringType("userId", ""); // Empty user id
                                            body.object(
                                                    "si",
                                                    si -> {
                                                        si.stringType("jwt", SI_JWT_STRING);
                                                        si.stringType("vot", P2.toString());
                                                    });
                                        })
                                .build())
                .willRespondWith()
                .status(400)
                .toPact();
    }

    @Test
    @PactTestFor(pactMethod = "emptyUserIdPostIdentityReturns400")
    void testEmptyUserIdPostIdentityReturns400(MockServer mockServer) {
        // Arrange
        var evcsPostIdentityDto = new EvcsPostIdentityDto("", null, EVCS_STORED_IDENTITY_DTO);
        var underTest = new EvcsClient(mockConfigService);

        // Act & Assert
        var exception =
                assertThrows(
                        EvcsServiceException.class,
                        () -> {
                            underTest.storeUserIdentity(evcsPostIdentityDto);
                        });
        assertEquals(
                ErrorResponse.RECEIVED_NON_200_RESPONSE_STATUS_CODE, exception.getErrorResponse());
        assertEquals(HTTPResponse.SC_SERVER_ERROR, exception.getResponseCode());
    }

    @Pact(provider = "EvcsProvider", consumer = "IpvCoreBack")
    public RequestResponsePact nullSiPostIdentityReturns400(PactDslWithProvider builder) {
        return builder.given("EVCS client exist")
                .given("test-evcs-api-key is a valid API key")
                .uponReceiving("A request to create a stored identity in EVCS.")
                .path("/identity")
                .method("POST")
                .headers(
                        Map.of(
                                "x-api-key",
                                EVCS_API_KEY,
                                CONTENT_TYPE,
                                ContentType.APPLICATION_JSON.toString()))
                .body(
                        newJsonBody(
                                        body -> {
                                            body.stringType("userId", TEST_USER_ID);
                                            // Null si
                                        })
                                .build())
                .willRespondWith()
                .status(400)
                .toPact();
    }

    @Test
    @PactTestFor(pactMethod = "nullSiPostIdentityReturns400")
    void testNullSiPostIdentityReturns400(MockServer mockServer) {
        // Arrange
        var evcsPostIdentityDto = new EvcsPostIdentityDto(TEST_USER_ID, null, null);
        var underTest = new EvcsClient(mockConfigService);

        // Act & Assert
        var exception =
                assertThrows(
                        EvcsServiceException.class,
                        () -> {
                            underTest.storeUserIdentity(evcsPostIdentityDto);
                        });
        assertEquals(
                ErrorResponse.RECEIVED_NON_200_RESPONSE_STATUS_CODE, exception.getErrorResponse());
        assertEquals(HTTPResponse.SC_SERVER_ERROR, exception.getResponseCode());
    }

    @Pact(provider = "EvcsProvider", consumer = "IpvCoreBack")
    public RequestResponsePact invalidSiPostIdentityReturns400(PactDslWithProvider builder) {
        return builder.given("EVCS client exist")
                .given("test-evcs-api-key is a valid API key")
                .uponReceiving("A request to create a stored identity in EVCS.")
                .path("/identity")
                .method("POST")
                .headers(
                        Map.of(
                                "x-api-key",
                                EVCS_API_KEY,
                                CONTENT_TYPE,
                                ContentType.APPLICATION_JSON.toString()))
                .body(
                        newJsonBody(
                                        body -> {
                                            body.stringType("userId", TEST_USER_ID);
                                            body.object(
                                                    "si",
                                                    si -> {
                                                        // Missing vot
                                                        si.stringType("jwt", SI_JWT_STRING);
                                                    });
                                        })
                                .build())
                .willRespondWith()
                .status(400)
                .toPact();
    }

    @Test
    @PactTestFor(pactMethod = "invalidSiPostIdentityReturns400")
    void testInvalidSiPostIdentityReturns400(MockServer mockServer) {
        // Arrange
        var evcsPostIdentityDto =
                new EvcsPostIdentityDto(TEST_USER_ID, null, EVCS_INVALID_STORED_IDENTITY_DTO);
        var underTest = new EvcsClient(mockConfigService);

        // Act & Assert
        var exception =
                assertThrows(
                        EvcsServiceException.class,
                        () -> {
                            underTest.storeUserIdentity(evcsPostIdentityDto);
                        });
        assertEquals(
                ErrorResponse.RECEIVED_NON_200_RESPONSE_STATUS_CODE, exception.getErrorResponse());
        assertEquals(HTTPResponse.SC_SERVER_ERROR, exception.getResponseCode());
    }

    @Pact(provider = "EvcsProvider", consumer = "IpvCoreBack")
    public RequestResponsePact forbiddenPostIdentityReturns403(PactDslWithProvider builder) {
        return builder.given("EVCS client exist")
                .given("invalid-api-key is an invalid API key")
                .uponReceiving("A request to create a stored identity in EVCS.")
                .path("/identity")
                .method("POST")
                .headers(
                        Map.of(
                                "x-api-key",
                                EVCS_INVALID_API_KEY,
                                CONTENT_TYPE,
                                ContentType.APPLICATION_JSON.toString()))
                .body(
                        newJsonBody(
                                        body -> {
                                            body.stringType("userId", TEST_USER_ID);
                                            body.object(
                                                    "si",
                                                    si -> {
                                                        si.stringType("jwt", SI_JWT_STRING);
                                                        si.stringType("vot", P2.toString());
                                                    });
                                        })
                                .build())
                .willRespondWith()
                .status(403)
                .toPact();
    }

    @Test
    @PactTestFor(pactMethod = "forbiddenPostIdentityReturns403")
    void testForbiddenPostIdentityReturns403(MockServer mockServer) {
        // Arrange
        lenient()
                .when(mockConfigService.getSecret(ConfigurationVariable.EVCS_API_KEY))
                .thenReturn(EVCS_INVALID_API_KEY);
        var evcsPostIdentityDto =
                new EvcsPostIdentityDto(TEST_USER_ID, null, EVCS_STORED_IDENTITY_DTO);
        var underTest = new EvcsClient(mockConfigService);

        // Act & Assert
        var exception =
                assertThrows(
                        EvcsServiceException.class,
                        () -> {
                            underTest.storeUserIdentity(evcsPostIdentityDto);
                        });
        assertEquals(
                ErrorResponse.RECEIVED_NON_200_RESPONSE_STATUS_CODE, exception.getErrorResponse());
        assertEquals(HTTPResponse.SC_SERVER_ERROR, exception.getResponseCode());
    }

    // POST /identity/invalidate
    @Pact(provider = "EvcsProvider", consumer = "IpvCoreBack")
    public RequestResponsePact postIdentityInvalidateReturns204(PactDslWithProvider builder) {
        return builder.given("EVCS client exist")
                .given("test-evcs-api-key is a valid API key")
                .uponReceiving("A request to invalidate a EVCS user identity")
                .path("/identity/invalidate")
                .method("POST")
                .headers(
                        Map.of(
                                "x-api-key",
                                EVCS_API_KEY,
                                CONTENT_TYPE,
                                ContentType.APPLICATION_JSON.toString()))
                .body(
                        newJsonBody(
                                        body -> {
                                            body.stringType("userId", TEST_USER_ID);
                                        })
                                .build())
                .willRespondWith()
                .status(204)
                .toPact();
    }

    @Test
    @PactTestFor(pactMethod = "postIdentityInvalidateReturns204")
    void testPostIdentityInvalidateReturns204(MockServer mockServer) throws EvcsServiceException {
        // Arrange
        var underTest = new EvcsClient(mockConfigService);

        // Act
        var response = underTest.invalidateStoredIdentityRecord(TEST_USER_ID);

        // Assert
        assertEquals(204, response.statusCode());
    }

    @Pact(provider = "EvcsProvider", consumer = "IpvCoreBack")
    public RequestResponsePact nullUserIdPostIdentityInvalidateReturns400(
            PactDslWithProvider builder) {
        // Null user id
        return builder.given("EVCS client exist")
                .given("test-evcs-api-key is a valid API key")
                .uponReceiving("A request to invalidate a EVCS user identity, with an null user id")
                .path("/identity/invalidate")
                .method("POST")
                .headers(
                        Map.of(
                                "x-api-key",
                                EVCS_API_KEY,
                                CONTENT_TYPE,
                                ContentType.APPLICATION_JSON.toString()))
                .body(newJsonBody(body -> body.nullValue("userId")).build())
                .willRespondWith()
                .status(400)
                .toPact();
    }

    @Test
    @PactTestFor(pactMethod = "nullUserIdPostIdentityInvalidateReturns400")
    void testNullUserIdPostIdentityInvalidateReturns400(MockServer mockServer) {
        // Arrange
        var underTest = new EvcsClient(mockConfigService);

        // Act & Assert
        var exception =
                assertThrows(
                        EvcsServiceException.class,
                        () -> {
                            underTest.invalidateStoredIdentityRecord(null);
                        });
        assertEquals(
                ErrorResponse.RECEIVED_NON_200_RESPONSE_STATUS_CODE, exception.getErrorResponse());
        assertEquals(HTTPResponse.SC_SERVER_ERROR, exception.getResponseCode());
    }

    @Pact(provider = "EvcsProvider", consumer = "IpvCoreBack")
    public RequestResponsePact emptyUserIdPostIdentityInvalidateReturns400(
            PactDslWithProvider builder) {
        return builder.given("EVCS client exist")
                .given("test-evcs-api-key is a valid API key")
                .uponReceiving(
                        "A request to invalidate a EVCS user identity, with an empty user id")
                .path("/identity/invalidate")
                .method("POST")
                .headers(
                        Map.of(
                                "x-api-key",
                                EVCS_API_KEY,
                                CONTENT_TYPE,
                                ContentType.APPLICATION_JSON.toString()))
                .body(
                        newJsonBody(
                                        body -> {
                                            body.stringType("userId", "");
                                        })
                                .build())
                .willRespondWith()
                .status(400)
                .toPact();
    }

    @Test
    @PactTestFor(pactMethod = "emptyUserIdPostIdentityInvalidateReturns400")
    void testEmptyUserIdPostIdentityInvalidateReturns400(MockServer mockServer) {
        // Arrange
        var underTest = new EvcsClient(mockConfigService);

        // Act & Assert
        var exception =
                assertThrows(
                        EvcsServiceException.class,
                        () -> {
                            underTest.invalidateStoredIdentityRecord("");
                        });
        assertEquals(
                ErrorResponse.RECEIVED_NON_200_RESPONSE_STATUS_CODE, exception.getErrorResponse());
        assertEquals(HTTPResponse.SC_SERVER_ERROR, exception.getResponseCode());
    }

    @Pact(provider = "EvcsProvider", consumer = "IpvCoreBack")
    public RequestResponsePact forbiddenPostIdentityInvalidateReturns403(
            PactDslWithProvider builder) {
        return builder.given("EVCS client exist")
                .given("invalid-api-key is an invalid API key")
                .uponReceiving("A request to invalidate a EVCS user identity")
                .path("/identity/invalidate")
                .method("POST")
                .headers(
                        Map.of(
                                "x-api-key",
                                EVCS_INVALID_API_KEY,
                                CONTENT_TYPE,
                                ContentType.APPLICATION_JSON.toString()))
                .body(
                        newJsonBody(
                                        body -> {
                                            body.stringType("userId", TEST_USER_ID);
                                        })
                                .build())
                .willRespondWith()
                .status(403)
                .toPact();
    }

    @Test
    @PactTestFor(pactMethod = "forbiddenPostIdentityInvalidateReturns403")
    void testForbiddenPostIdentityInvalidateReturns403(MockServer mockServer) {
        // Arrange
        lenient()
                .when(mockConfigService.getSecret(ConfigurationVariable.EVCS_API_KEY))
                .thenReturn(EVCS_INVALID_API_KEY);
        var underTest = new EvcsClient(mockConfigService);

        // Act & Assert
        var exception =
                assertThrows(
                        EvcsServiceException.class,
                        () -> {
                            underTest.invalidateStoredIdentityRecord(TEST_USER_ID);
                        });
        assertEquals(
                ErrorResponse.RECEIVED_NON_200_RESPONSE_STATUS_CODE, exception.getErrorResponse());
        assertEquals(HTTPResponse.SC_SERVER_ERROR, exception.getResponseCode());
    }

    @Pact(provider = "EvcsProvider", consumer = "IpvCoreBack")
    public RequestResponsePact notFoundPostIdentityInvalidateReturns404(
            PactDslWithProvider builder) {
        return builder.given("EVCS client exist")
                .given("test-evcs-api-key is a valid API key")
                .given("No user exists with id invalid-user-id")
                .uponReceiving("A request to invalidate a EVCS user identity")
                .path("/identity/invalidate")
                .method("POST")
                .headers(
                        Map.of(
                                "x-api-key",
                                EVCS_API_KEY,
                                CONTENT_TYPE,
                                ContentType.APPLICATION_JSON.toString()))
                .body(
                        newJsonBody(
                                        body -> {
                                            body.stringType("userId", INVALID_USER_ID);
                                        })
                                .build())
                .willRespondWith()
                .status(404)
                .toPact();
    }

    @Test
    @PactTestFor(pactMethod = "notFoundPostIdentityInvalidateReturns404")
    void testNotFoundPostIdentityInvalidateReturns404(MockServer mockServer)
            throws EvcsServiceException {
        // Arrange
        var underTest = new EvcsClient(mockConfigService);

        // Act
        var response = underTest.invalidateStoredIdentityRecord(TEST_USER_ID);

        // Assert
        assertEquals(404, response.statusCode());
    }
}
