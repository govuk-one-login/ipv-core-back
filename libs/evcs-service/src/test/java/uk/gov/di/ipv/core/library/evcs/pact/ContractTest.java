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

    private static final String DCMAW_PASSPORT_VC_STRING =
            "eyJ0eXAiOiJKV1QiLCJhbGciOiJFUzI1NiJ9.eyJpc3MiOiJodHRwczovL3Jldmlldy1iLnN0YWdpbmcuYWNjb3VudC5nb3YudWsiLCJzdWIiOiJ1cm46dXVpZDowMWE0NDM0Mi1lNjQzLTRjYTktODMwNi1hOGUwNDQwOTJmYjAiLCJuYmYiOjE3MDU5ODY1MjEsImlhdCI6MTcwNTk4NjUyMSwidmMiOnsiY3JlZGVudGlhbFN1YmplY3QiOnsiYWRkcmVzcyI6W3siYWRkcmVzc0NvdW50cnkiOiJHQiIsImFkZHJlc3NMb2NhbGl0eSI6IkdSRUFUIE1JU1NFTkRFTiIsImJ1aWxkaW5nTmFtZSI6IkNPWSBQT05EIEJVU0lORVNTIFBBUksiLCJidWlsZGluZ051bWJlciI6IjE2IiwiZGVwZW5kZW50QWRkcmVzc0xvY2FsaXR5IjoiTE9ORyBFQVRPTiIsImRlcGVuZGVudFN0cmVldE5hbWUiOiJLSU5HUyBQQVJLIiwiZG91YmxlRGVwZW5kZW50QWRkcmVzc0xvY2FsaXR5IjoiU09NRSBESVNUUklDVCIsIm9yZ2FuaXNhdGlvbk5hbWUiOiJGSU5DSCBHUk9VUCIsInBvc3RhbENvZGUiOiJIUDE2IDBBTCIsInN0cmVldE5hbWUiOiJCSUcgU1RSRUVUIiwic3ViQnVpbGRpbmdOYW1lIjoiVU5JVCAyQiIsInVwcm4iOjEwMDEyMDAxMjA3N31dLCJiaXJ0aERhdGUiOlt7InZhbHVlIjoiMTk2NS0wNy0wOCJ9XSwibmFtZSI6W3sibmFtZVBhcnRzIjpbeyJ0eXBlIjoiR2l2ZW5OYW1lIiwidmFsdWUiOiJNT1JHQU4ifSx7InR5cGUiOiJGYW1pbHlOYW1lIiwidmFsdWUiOiJTQVJBSCBNRVJFRFlUSCJ9XX1dLCJwYXNzcG9ydCI6W3siZG9jdW1lbnROdW1iZXIiOiIzMjE2NTQ5ODciLCJleHBpcnlEYXRlIjoiMjAzMC0wMS0wMSIsImljYW9Jc3N1ZXJDb2RlIjoiR0JSIn1dfSwiZXZpZGVuY2UiOlt7ImFjdGl2aXR5SGlzdG9yeVNjb3JlIjoxLCJjaGVja0RldGFpbHMiOlt7ImFjdGl2aXR5RnJvbSI6IjIwMTktMDEtMDEiLCJjaGVja01ldGhvZCI6InZyaSIsImlkZW50aXR5Q2hlY2tQb2xpY3kiOiJwdWJsaXNoZWQifSx7ImJpb21ldHJpY1ZlcmlmaWNhdGlvblByb2Nlc3NMZXZlbCI6MywiY2hlY2tNZXRob2QiOiJidnIifV0sInN0cmVuZ3RoU2NvcmUiOjQsInR4biI6ImJjZDIzNDYiLCJ0eXBlIjoiSWRlbnRpdHlDaGVjayIsInZhbGlkaXR5U2NvcmUiOjJ9XSwidHlwZSI6WyJWZXJpZmlhYmxlQ3JlZGVudGlhbCIsIklkZW50aXR5Q2hlY2tDcmVkZW50aWFsIl19fQ.hjJcmLEEIbG6J1Ik2vW5oRhpazL1SvvuvyBe5T62VtlNik5zsKwPtqly0eDeJeiCp4oxtcmBfG1APMNRasbk8A";
    private static final String ADDRESS_VC_STRING =
            "eyJ0eXAiOiJKV1QiLCJhbGciOiJFUzI1NiJ9.eyJpc3MiOiJodHRwczovL3Jldmlldy1hLmludGVncmF0aW9uLmFjY291bnQuZ292LnVrIiwic3ViIjoidXJuOnV1aWQ6ZTZlMmUzMjQtNWI2Ni00YWQ2LTgzMzgtODNmOWY4MzdlMzQ1IiwibmJmIjoxNjU4ODI5NzIwLCJpYXQiOjE2NTg4Mjk3MjAsInZjIjp7ImNyZWRlbnRpYWxTdWJqZWN0Ijp7ImFkZHJlc3MiOlt7ImFkZHJlc3NDb3VudHJ5IjoiR0IiLCJhZGRyZXNzTG9jYWxpdHkiOiJCQVRIIiwiYnVpbGRpbmdOYW1lIjoiIiwiYnVpbGRpbmdOdW1iZXIiOiI4IiwicG9zdGFsQ29kZSI6IkJBMiA1QUEiLCJzdHJlZXROYW1lIjoiSEFETEVZIFJPQUQiLCJ1cHJuIjoxMDAxMjAwMTIwNzcsInZhbGlkVW50aWwiOiIyMDAwLTAxLTAxIn1dfSwidHlwZSI6WyJWZXJpZmlhYmxlQ3JlZGVudGlhbCIsIkFkZHJlc3NDcmVkZW50aWFsIl19fQ.tJr8joysbRzbyT0e8qRWTay88cNFFa9DA5Qyc6rHvwUxlMYdIUzDnVQYfb4x8O_beUHaxxn5NiMCua2qd3xFHw";
    private static final String FRAUD_VC_STRING =
            "eyJ0eXAiOiJKV1QiLCJhbGciOiJFUzI1NiJ9.eyJpc3MiOiJodHRwczovL3Jldmlldy1mLmludGVncmF0aW9uLmFjY291bnQuZ292LnVrIiwic3ViIjoidXJuOnV1aWQ6ZTZlMmUzMjQtNWI2Ni00YWQ2LTgzMzgtODNmOWY4MzdlMzQ1IiwibmJmIjoxNzQ5NDY2MjY2LCJpYXQiOjE3NDk0NjYyNjYsInZjIjp7ImNyZWRlbnRpYWxTdWJqZWN0Ijp7ImFkZHJlc3MiOlt7ImFkZHJlc3NDb3VudHJ5IjoiR0IiLCJhZGRyZXNzTG9jYWxpdHkiOiJCQVRIIiwiYnVpbGRpbmdOYW1lIjoiIiwiYnVpbGRpbmdOdW1iZXIiOiI4IiwicG9zdGFsQ29kZSI6IkJBMiA1QUEiLCJzdHJlZXROYW1lIjoiSEFETEVZIFJPQUQiLCJ1cHJuIjoxMDAxMjAwMTIwNzcsInZhbGlkVW50aWwiOiIyMDAwLTAxLTAxIn1dLCJiaXJ0aERhdGUiOlt7InZhbHVlIjoiMTk1OS0wOC0yMyJ9XSwibmFtZSI6W3sibmFtZVBhcnRzIjpbeyJ0eXBlIjoiR2l2ZW5OYW1lIiwidmFsdWUiOiJLRU5ORVRIIn0seyJ0eXBlIjoiRmFtaWx5TmFtZSIsInZhbHVlIjoiREVDRVJRVUVJUkEifV19XX0sImV2aWRlbmNlIjpbeyJpZGVudGl0eUZyYXVkU2NvcmUiOjEsInR4biI6IlJCMDAwMTAzNDkwMDg3IiwidHlwZSI6IklkZW50aXR5Q2hlY2sifV0sInR5cGUiOlsiVmVyaWZpYWJsZUNyZWRlbnRpYWwiLCJJZGVudGl0eUNoZWNrQ3JlZGVudGlhbCJdfX0.LDY6jIPXpHxJuDPkSQlcUsHOL_y4j3ZdGLwhK8vCAceXVhtR1XPXljpeW6aUcj3Q8m7Ox55KB9Le9TPrF9xr1Q";
    private static final String SI_STRING =
            "eyJ0eXAiOiJKV1QiLCJhbGciOiJFUzI1NiJ9.eyJpc3MiOiJodHRwczovL2lkZW50aXR5LmFjY291bnQuZ292LnVrIiwic3ViIjoidGVzdC11c2VyLWlkIiwiYXVkIjoiaHR0cHM6Ly9yZXVzZS1pZGVudGl0eS5hY2NvdW50Lmdvdi51ayIsIm5iZiI6MjY1ODgyOTcyMCwiaWF0IjoyNjU4ODI5NzIwLCJ2b3QiOiJQMiIsImNyZWRlbnRpYWxzIjpbImhqSmNtTEVFSWJHNkoxSWsydlc1b1JocGF6TDFTdnZ1dnlCZTVUNjJWdGxOaWs1enNLd1B0cWx5MGVEZUplaUNwNG94dGNtQmZHMUFQTU5SYXNiazhBIiwidEpyOGpveXNiUnpieVQwZThxUldUYXk4OGNORkZhOURBNVF5YzZySHZ3VXhsTVlkSVV6RG5WUVlmYjR4OE9fYmVVSGF4eG41TmlNQ3VhMnFkM3hGSHciLCJMRFk2aklQWHBIeEp1RFBrU1FsY1VzSE9MX3k0ajNaZEdMd2hLOHZDQWNlWFZodFIxWFBYbGpwZVc2YVVjajNROG03T3g1NUtCOUxlOVRQckY5eHIxUSJdLCJjbGFpbXMiOnt9fQ.omMIO4KF1uPKlWh252GIX21MgCfrH6qoQGezYcD_yZWDobZ5H0L3dCvQxEt7SVXLWmxtBsoQpv4Lf8kwfGVI2Q";
    private static final EvcsPutUserVCsDto EVCS_PUT_NEW_VCS_DTO =
            new EvcsPutUserVCsDto(
                    TEST_USER_ID,
                    List.of(
                            new EvcsCreateUserVCsDto(
                                    ADDRESS_VC_STRING, EvcsVCState.CURRENT, Map.of(), ONLINE)),
                    null);

    private static final EvcsPutUserVCsDto EVCS_PUT_UPDATED_VCS_DTO =
            new EvcsPutUserVCsDto(
                    TEST_USER_ID,
                    List.of(
                            new EvcsCreateUserVCsDto(
                                    ADDRESS_VC_STRING, EvcsVCState.HISTORIC, Map.of(), ONLINE)),
                    null);

    private static final EvcsPutUserVCsDto EVCS_PUT_P2_SI_AND_VCS_DTO =
            new EvcsPutUserVCsDto(
                    TEST_USER_ID,
                    List.of(
                            new EvcsCreateUserVCsDto(
                                    DCMAW_PASSPORT_VC_STRING,
                                    EvcsVCState.CURRENT,
                                    Map.of(),
                                    ONLINE),
                            new EvcsCreateUserVCsDto(
                                    ADDRESS_VC_STRING, EvcsVCState.CURRENT, Map.of(), ONLINE),
                            new EvcsCreateUserVCsDto(
                                    FRAUD_VC_STRING, EvcsVCState.CURRENT, Map.of(), ONLINE)),
                    new EvcsStoredIdentityDto(SI_STRING, Vot.P2));

    private static final EvcsPutUserVCsDto DUPLICATE_CONFLICTING_VCS_DTO =
            new EvcsPutUserVCsDto(
                    TEST_USER_ID,
                    List.of(
                            new EvcsCreateUserVCsDto(
                                    VC_STRING, EvcsVCState.CURRENT, Map.of(), ONLINE),
                            new EvcsCreateUserVCsDto(VC_STRING, PENDING_RETURN, Map.of(), ONLINE)),
                    null);

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
    public RequestResponsePact putNewVcs(PactDslWithProvider builder) {
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
                                                    "vcs",
                                                    vcDtos -> {
                                                        vcDtos.object(
                                                                vcDto -> {
                                                                    vcDto.stringType(
                                                                            "vc",
                                                                            ADDRESS_VC_STRING);
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
                                        })
                                .build())
                .willRespondWith()
                .status(202)
                .toPact();
    }

    @Test
    @PactTestFor(pactMethod = "putNewVcs")
    void testPutNewVcs(MockServer mockServer) throws EvcsServiceException {
        // Arrange
        var evcsClient = new EvcsClient(mockConfigService);

        // Act
        var response = evcsClient.storeUserVCs(EVCS_PUT_NEW_VCS_DTO);

        // Assert
        assertEquals(202, response.statusCode());
    }

    @Pact(provider = "EvcsProvider", consumer = "IpvCoreBack")
    public RequestResponsePact putUpdatedVcs(PactDslWithProvider builder) {
        return builder.given("VC already exists in EVCS")
                .given(String.format("%s is a valid EVCS API key", EVCS_API_KEY))
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
                                                    "vcs",
                                                    vcDtos -> {
                                                        vcDtos.object(
                                                                vcDto -> {
                                                                    vcDto.stringType(
                                                                            "vc",
                                                                            ADDRESS_VC_STRING);
                                                                    vcDto.stringType(
                                                                            "state",
                                                                            EvcsVCState.HISTORIC
                                                                                    .toString());
                                                                    vcDto.object(
                                                                            "metadata", vc -> {});
                                                                    vcDto.stringType(
                                                                            "provenance",
                                                                            ONLINE.toString());
                                                                });
                                                    });
                                        })
                                .build())
                .willRespondWith()
                .status(202)
                .toPact();
    }

    @Test
    @PactTestFor(pactMethod = "putUpdatedVcs")
    void testPutUpdatedVcs(MockServer mockServer) throws EvcsServiceException {
        // Arrange
        var evcsClient = new EvcsClient(mockConfigService);

        // Act
        var response = evcsClient.storeUserVCs(EVCS_PUT_UPDATED_VCS_DTO);

        // Assert
        assertEquals(202, response.statusCode());
    }

    @Pact(provider = "EvcsProvider", consumer = "IpvCoreBack")
    public RequestResponsePact putVcsAndStoredIdentity(PactDslWithProvider builder) {
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
                                                    "vcs",
                                                    vcDtos -> {
                                                        vcDtos.object(
                                                                vcDto -> {
                                                                    vcDto.stringType(
                                                                            "vc",
                                                                            DCMAW_PASSPORT_VC_STRING);
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
                                                                            ADDRESS_VC_STRING);
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
                                                                            "vc", FRAUD_VC_STRING);
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
    @PactTestFor(pactMethod = "putVcsAndStoredIdentity")
    void testPutVcsAndStoredIdentity(MockServer mockServer) throws EvcsServiceException {
        // Arrange
        var evcsClient = new EvcsClient(mockConfigService);

        // Act
        var response = evcsClient.storeUserVCs(EVCS_PUT_P2_SI_AND_VCS_DTO);

        // Assert
        assertEquals(202, response.statusCode());
    }

    @Pact(provider = "EvcsProvider", consumer = "IpvCoreBack")
    public RequestResponsePact putDuplicateVcsOfDifferentStates(PactDslWithProvider builder) {
        return builder.given(String.format("%s is a valid EVCS API key", EVCS_API_KEY))
                .uponReceiving("A bad request with duplicate VCs with different states")
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
                                                    "vcs",
                                                    vcs -> {
                                                        vcs.object(
                                                                vc -> {
                                                                    vc.stringType(
                                                                            "vc",
                                                                            DCMAW_PASSPORT_VC_STRING);
                                                                    vc.stringType(
                                                                            "state",
                                                                            EvcsVCState.CURRENT
                                                                                    .toString());
                                                                    vc.object(
                                                                            "metadata", meta -> {});
                                                                    vc.stringType(
                                                                            "provenance",
                                                                            ONLINE.toString());
                                                                });
                                                        vcs.object(
                                                                vc -> {
                                                                    vc.stringType(
                                                                            "vc",
                                                                            DCMAW_PASSPORT_VC_STRING); // same VC
                                                                    vc.stringType(
                                                                            "state",
                                                                            PENDING_RETURN
                                                                                    .toString()); // conflicting state
                                                                    vc.object(
                                                                            "metadata", meta -> {});
                                                                    vc.stringType(
                                                                            "provenance",
                                                                            ONLINE.toString());
                                                                });
                                                    });
                                        })
                                .build())
                .willRespondWith()
                .status(400)
                .body(
                        newJsonBody(
                                        body -> {
                                            body.stringType(
                                                    "error",
                                                    "Duplicate VCs with conflicting state detected");
                                        })
                                .build())
                .toPact();
    }

    @Test
    @PactTestFor(pactMethod = "putDuplicateVcsOfDifferentStates")
    void testPutDuplicateVcsOfDifferentStates(MockServer mockServer) {
        // Arrange
        var evcsClient = new EvcsClient(mockConfigService);

        // Act & Assert
        assertThrows(
                EvcsServiceException.class,
                () -> {
                    evcsClient.storeUserVCs(DUPLICATE_CONFLICTING_VCS_DTO);
                });
    }

    @Pact(provider = "EvcsProvider", consumer = "IpvCoreBack")
    public RequestResponsePact putVcsWithoutApiKey(PactDslWithProvider builder) {
        return builder.uponReceiving("A PUT request with missing or invalid API key")
                .path("/vcs")
                .method("PUT")
                .headers(Map.of(CONTENT_TYPE, ContentType.APPLICATION_JSON.toString()))
                .body(
                        newJsonBody(
                                        dto -> {
                                            dto.stringType("userId", TEST_USER_ID);
                                            dto.array(
                                                    "vcs",
                                                    vcs -> {
                                                        vcs.object(
                                                                vc -> {
                                                                    vc.stringType(
                                                                            "vc",
                                                                            DCMAW_PASSPORT_VC_STRING);
                                                                    vc.stringType(
                                                                            "state",
                                                                            EvcsVCState.CURRENT
                                                                                    .toString());
                                                                    vc.object(
                                                                            "metadata", meta -> {});
                                                                    vc.stringType(
                                                                            "provenance",
                                                                            ONLINE.toString());
                                                                });
                                                    });
                                        })
                                .build())
                .willRespondWith()
                .status(403)
                .toPact();
    }

    @Test
    @PactTestFor(pactMethod = "putVcsWithoutApiKey")
    void testPutVcsWithoutApiKey(MockServer mockServer) {
        // Arrange
        var evcsClient = new EvcsClient(mockConfigService);

        // Act & Assert
        assertThrows(
                EvcsServiceException.class,
                () -> {
                    evcsClient.storeUserVCs(EVCS_PUT_NEW_VCS_DTO);
                });
    }
}
