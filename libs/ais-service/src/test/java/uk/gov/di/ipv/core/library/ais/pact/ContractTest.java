package uk.gov.di.ipv.core.library.ais.pact;

import au.com.dius.pact.consumer.MockServer;
import au.com.dius.pact.consumer.dsl.DslPart;
import au.com.dius.pact.consumer.dsl.PactDslWithProvider;
import au.com.dius.pact.consumer.junit.MockServerConfig;
import au.com.dius.pact.consumer.junit5.PactConsumerTestExt;
import au.com.dius.pact.consumer.junit5.PactTestFor;
import au.com.dius.pact.core.model.RequestResponsePact;
import au.com.dius.pact.core.model.annotations.Pact;
import org.apache.hc.core5.http.ContentType;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import uk.gov.di.ipv.core.library.ais.client.AisClient;
import uk.gov.di.ipv.core.library.ais.exception.AisClientException;
import uk.gov.di.ipv.core.library.config.ConfigurationVariable;
import uk.gov.di.ipv.core.library.domain.AisInterventionType;
import uk.gov.di.ipv.core.library.service.ConfigService;

import java.util.Map;

import static au.com.dius.pact.consumer.dsl.LambdaDsl.newJsonBody;
import static org.apache.hc.core5.http.HttpHeaders.CONTENT_TYPE;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.Mockito.when;

@ExtendWith(MockitoExtension.class)
@ExtendWith(PactConsumerTestExt.class)
@PactTestFor(providerName = "AccountInterventionServiceProvider")
@MockServerConfig(hostInterface = "localhost")
class ContractTest {
    private static final String TEST_USER_ID = "test-user-id";
    private static final Long CURRENT_TIME = 1696969322935L;
    @Mock ConfigService mockConfigService;

    @Pact(provider = "AccountInterventionServiceProvider", consumer = "IpvCoreBack")
    public RequestResponsePact validGetAccountInterventionRequestReturnsNoInterventionWith200(
            PactDslWithProvider builder) throws Exception {
        return buildRequestResponsePact(builder, AisInterventionType.AIS_NO_INTERVENTION);
    }

    @Test
    @PactTestFor(pactMethod = "validGetAccountInterventionRequestReturnsNoInterventionWith200")
    void getUserAccountInterventionsReturnsNoInterventionsWith200(MockServer mockServer)
            throws Exception {
        // Arrange
        when(mockConfigService.getParameter(ConfigurationVariable.AIS_API_BASE_URL))
                .thenReturn(getMockAisBaseUrl(mockServer));

        // Act
        var aisClientUnderTest = new AisClient(mockConfigService);
        var interventions = aisClientUnderTest.getAccountInterventionStatus(TEST_USER_ID);

        // Assert
        assertFalse(interventions.getState().isReproveIdentity());
        assertEquals(
                AisInterventionType.AIS_NO_INTERVENTION,
                interventions.getIntervention().getDescription());
    }

    @Pact(provider = "AccountInterventionServiceProvider", consumer = "IpvCoreBack")
    public RequestResponsePact validGetAccountInterventionRequestReturnsSuspendedWith200(
            PactDslWithProvider builder) throws Exception {
        return buildRequestResponsePact(builder, AisInterventionType.AIS_ACCOUNT_SUSPENDED);
    }

    @Test
    @PactTestFor(pactMethod = "validGetAccountInterventionRequestReturnsSuspendedWith200")
    void getUserAccountInterventionsReturnsSuspendedWith200(MockServer mockServer)
            throws Exception {
        // Arrange
        when(mockConfigService.getParameter(ConfigurationVariable.AIS_API_BASE_URL))
                .thenReturn(getMockAisBaseUrl(mockServer));

        // Act
        var aisClientUnderTest = new AisClient(mockConfigService);
        var interventions = aisClientUnderTest.getAccountInterventionStatus(TEST_USER_ID);

        // Assert
        assertFalse(interventions.getState().isReproveIdentity());
        assertEquals(
                AisInterventionType.AIS_ACCOUNT_SUSPENDED,
                interventions.getIntervention().getDescription());
    }

    @Pact(provider = "AccountInterventionServiceProvider", consumer = "IpvCoreBack")
    public RequestResponsePact validGetAccountInterventionRequestReturnsUnsuspendedWith200(
            PactDslWithProvider builder) throws Exception {
        return buildRequestResponsePact(builder, AisInterventionType.AIS_ACCOUNT_UNSUSPENDED);
    }

    @Test
    @PactTestFor(pactMethod = "validGetAccountInterventionRequestReturnsUnsuspendedWith200")
    void getUserAccountInterventionsReturnsUnsuspendedWith200(MockServer mockServer)
            throws Exception {
        // Arrange
        when(mockConfigService.getParameter(ConfigurationVariable.AIS_API_BASE_URL))
                .thenReturn(getMockAisBaseUrl(mockServer));

        // Act
        var aisClientUnderTest = new AisClient(mockConfigService);
        var interventions = aisClientUnderTest.getAccountInterventionStatus(TEST_USER_ID);

        // Assert
        assertFalse(interventions.getState().isReproveIdentity());
        assertEquals(
                AisInterventionType.AIS_ACCOUNT_UNSUSPENDED,
                interventions.getIntervention().getDescription());
    }

    @Pact(provider = "AccountInterventionServiceProvider", consumer = "IpvCoreBack")
    public RequestResponsePact validGetAccountInterventionRequestReturnsBlockedWith200(
            PactDslWithProvider builder) throws Exception {
        return buildRequestResponsePact(builder, AisInterventionType.AIS_ACCOUNT_BLOCKED);
    }

    @Test
    @PactTestFor(pactMethod = "validGetAccountInterventionRequestReturnsBlockedWith200")
    void getUserAccountInterventionsReturnsBlockedWith200(MockServer mockServer) throws Exception {
        // Arrange
        when(mockConfigService.getParameter(ConfigurationVariable.AIS_API_BASE_URL))
                .thenReturn(getMockAisBaseUrl(mockServer));

        // Act
        var aisClientUnderTest = new AisClient(mockConfigService);
        var interventions = aisClientUnderTest.getAccountInterventionStatus(TEST_USER_ID);

        // Assert
        assertFalse(interventions.getState().isReproveIdentity());
        assertEquals(
                AisInterventionType.AIS_ACCOUNT_BLOCKED,
                interventions.getIntervention().getDescription());
    }

    @Pact(provider = "AccountInterventionServiceProvider", consumer = "IpvCoreBack")
    public RequestResponsePact validGetAccountInterventionRequestReturnsUnblockedWith200(
            PactDslWithProvider builder) throws Exception {
        return buildRequestResponsePact(builder, AisInterventionType.AIS_ACCOUNT_UNBLOCKED);
    }

    @Test
    @PactTestFor(pactMethod = "validGetAccountInterventionRequestReturnsUnblockedWith200")
    void getUserAccountInterventionsReturnsUnblockedWith200(MockServer mockServer)
            throws Exception {
        // Arrange
        when(mockConfigService.getParameter(ConfigurationVariable.AIS_API_BASE_URL))
                .thenReturn(getMockAisBaseUrl(mockServer));

        // Act
        var aisClientUnderTest = new AisClient(mockConfigService);
        var interventions = aisClientUnderTest.getAccountInterventionStatus(TEST_USER_ID);

        // Assert
        assertFalse(interventions.getState().isReproveIdentity());
        assertEquals(
                AisInterventionType.AIS_ACCOUNT_UNBLOCKED,
                interventions.getIntervention().getDescription());
    }

    @Pact(provider = "AccountInterventionServiceProvider", consumer = "IpvCoreBack")
    public RequestResponsePact validGetAccountInterventionRequestReturnsForcedPasswordResetWith200(
            PactDslWithProvider builder) throws Exception {
        return buildRequestResponsePact(
                builder, AisInterventionType.AIS_FORCED_USER_PASSWORD_RESET);
    }

    @Test
    @PactTestFor(pactMethod = "validGetAccountInterventionRequestReturnsForcedPasswordResetWith200")
    void getUserAccountInterventionsReturnsForcedPasswordResetWith200(MockServer mockServer)
            throws Exception {
        // Arrange
        when(mockConfigService.getParameter(ConfigurationVariable.AIS_API_BASE_URL))
                .thenReturn(getMockAisBaseUrl(mockServer));

        // Act
        var aisClientUnderTest = new AisClient(mockConfigService);
        var interventions = aisClientUnderTest.getAccountInterventionStatus(TEST_USER_ID);

        // Assert
        assertFalse(interventions.getState().isReproveIdentity());
        assertEquals(
                AisInterventionType.AIS_FORCED_USER_PASSWORD_RESET,
                interventions.getIntervention().getDescription());
    }

    @Pact(provider = "AccountInterventionServiceProvider", consumer = "IpvCoreBack")
    public RequestResponsePact
            validGetAccountInterventionRequestReturnsForcedUserIdentityVerifyWith200(
                    PactDslWithProvider builder) throws Exception {
        return buildRequestResponsePact(
                builder, AisInterventionType.AIS_FORCED_USER_IDENTITY_VERIFY);
    }

    @Test
    @PactTestFor(
            pactMethod = "validGetAccountInterventionRequestReturnsForcedUserIdentityVerifyWith200")
    void getUserAccountInterventionsReturnsForcedUserIdentityVerifyWith200(MockServer mockServer)
            throws Exception {
        // Arrange
        when(mockConfigService.getParameter(ConfigurationVariable.AIS_API_BASE_URL))
                .thenReturn(getMockAisBaseUrl(mockServer));

        // Act
        var aisClientUnderTest = new AisClient(mockConfigService);
        var interventions = aisClientUnderTest.getAccountInterventionStatus(TEST_USER_ID);

        // Assert
        assertTrue(interventions.getState().isReproveIdentity());
        assertEquals(
                AisInterventionType.AIS_FORCED_USER_IDENTITY_VERIFY,
                interventions.getIntervention().getDescription());
    }

    @Pact(provider = "AccountInterventionServiceProvider", consumer = "IpvCoreBack")
    public RequestResponsePact
            validGetAccountInterventionRequestReturnsForcedPasswordResetAndUserIdentityVerifyWith200(
                    PactDslWithProvider builder) throws Exception {
        return buildRequestResponsePact(
                builder, AisInterventionType.AIS_FORCED_USER_PASSWORD_RESET_AND_IDENTITY_VERIFY);
    }

    @Test
    @PactTestFor(
            pactMethod =
                    "validGetAccountInterventionRequestReturnsForcedPasswordResetAndUserIdentityVerifyWith200")
    void getUserAccountInterventionsReturnsForcedPasswordResetAndUserIdentityVerifyWith200(
            MockServer mockServer) throws Exception {
        // Arrange
        when(mockConfigService.getParameter(ConfigurationVariable.AIS_API_BASE_URL))
                .thenReturn(getMockAisBaseUrl(mockServer));

        // Act
        var aisClientUnderTest = new AisClient(mockConfigService);
        var interventions = aisClientUnderTest.getAccountInterventionStatus(TEST_USER_ID);

        // Assert
        assertTrue(interventions.getState().isReproveIdentity());
        assertEquals(
                AisInterventionType.AIS_FORCED_USER_PASSWORD_RESET_AND_IDENTITY_VERIFY,
                interventions.getIntervention().getDescription());
    }

    @Pact(provider = "AccountInterventionServiceProvider", consumer = "IpvCoreBack")
    public RequestResponsePact invalidGetAccountInterventionRequestReturns400(
            PactDslWithProvider builder) {
        return builder.given("AIS returns a 400 Bad Request response")
                .uponReceiving("an invalid request")
                .path("/ais/" + TEST_USER_ID)
                .method("GET")
                .willRespondWith()
                .status(400)
                .toPact();
    }

    @SuppressWarnings("java:S5976")
    @Test
    @PactTestFor(pactMethod = "invalidGetAccountInterventionRequestReturns400")
    void getUserAccountInterventionsReturns400Error(MockServer mockServer) {
        // Arrange
        when(mockConfigService.getParameter(ConfigurationVariable.AIS_API_BASE_URL))
                .thenReturn(getMockAisBaseUrl(mockServer));

        // Act/Assert
        var aisClientUnderTest = new AisClient(mockConfigService);
        assertThrows(
                AisClientException.class,
                () -> {
                    aisClientUnderTest.getAccountInterventionStatus(TEST_USER_ID);
                });
    }

    @Pact(provider = "AccountInterventionServiceProvider", consumer = "IpvCoreBack")
    public RequestResponsePact getAccountInterventionRequestReturns500(
            PactDslWithProvider builder) {
        return builder.given(
                        "AIS encounters an error and responds with a 500 Internal Server Error")
                .uponReceiving("a valid request")
                .path("/ais/" + TEST_USER_ID)
                .method("GET")
                .willRespondWith()
                .status(500)
                .toPact();
    }

    @SuppressWarnings("java:S4144")
    @Test
    @PactTestFor(pactMethod = "getAccountInterventionRequestReturns500")
    void getUserAccountInterventionsReturns500Error(MockServer mockServer) {
        // Arrange
        when(mockConfigService.getParameter(ConfigurationVariable.AIS_API_BASE_URL))
                .thenReturn(getMockAisBaseUrl(mockServer));

        // Act/Assert
        var aisClientUnderTest = new AisClient(mockConfigService);
        assertThrows(
                AisClientException.class,
                () -> {
                    aisClientUnderTest.getAccountInterventionStatus(TEST_USER_ID);
                });
    }

    @Pact(provider = "AccountInterventionServiceProvider", consumer = "IpvCoreBack")
    public RequestResponsePact getAccountInterventionRequestReturns502(
            PactDslWithProvider builder) {
        return builder.given("AIS returns a 502 Bad Gateway response")
                .uponReceiving("a valid request")
                .path("/ais/" + TEST_USER_ID)
                .method("GET")
                .willRespondWith()
                .status(502)
                .body(newJsonBody(body -> body.stringValue("message", "Bad Gateway")).build())
                .toPact();
    }

    @SuppressWarnings("java:S4144")
    @Test
    @PactTestFor(pactMethod = "getAccountInterventionRequestReturns502")
    void getUserAccountInterventionsReturns502Error(MockServer mockServer) {
        // Arrange
        when(mockConfigService.getParameter(ConfigurationVariable.AIS_API_BASE_URL))
                .thenReturn(getMockAisBaseUrl(mockServer));

        // Act/Assert
        var aisClientUnderTest = new AisClient(mockConfigService);
        assertThrows(
                AisClientException.class,
                () -> {
                    aisClientUnderTest.getAccountInterventionStatus(TEST_USER_ID);
                });
    }

    @Pact(provider = "AccountInterventionServiceProvider", consumer = "IpvCoreBack")
    public RequestResponsePact getAccountInterventionRequestReturns504(
            PactDslWithProvider builder) {
        return builder.given("AIS returns a 504 Gateway Timeout response")
                .uponReceiving("a valid request")
                .path("/ais/" + TEST_USER_ID)
                .method("GET")
                .willRespondWith()
                .status(504)
                .toPact();
    }

    @SuppressWarnings("java:S4144")
    @Test
    @PactTestFor(pactMethod = "getAccountInterventionRequestReturns504")
    void getUserAccountInterventionsReturns504Error(MockServer mockServer) {
        // Arrange
        when(mockConfigService.getParameter(ConfigurationVariable.AIS_API_BASE_URL))
                .thenReturn(getMockAisBaseUrl(mockServer));

        // Act/Assert
        var aisClientUnderTest = new AisClient(mockConfigService);
        assertThrows(
                AisClientException.class,
                () -> {
                    aisClientUnderTest.getAccountInterventionStatus(TEST_USER_ID);
                });
    }

    private String getMockAisBaseUrl(MockServer mockServer) {
        return "http://localhost:" + mockServer.getPort();
    }

    private static DslPart getResponseBodyByIntervention(AisInterventionType interventionType)
            throws Exception {
        switch (interventionType) {
            case AIS_NO_INTERVENTION -> {
                return generateAisResponseBody(
                        AisInterventionType.AIS_NO_INTERVENTION, false, false, false, false);
            }
            case AIS_ACCOUNT_SUSPENDED -> {
                return generateAisResponseBody(
                        AisInterventionType.AIS_ACCOUNT_SUSPENDED, false, true, false, false);
            }
            case AIS_ACCOUNT_UNSUSPENDED -> {
                return generateAisResponseBody(
                        AisInterventionType.AIS_ACCOUNT_UNSUSPENDED, false, false, false, false);
            }
            case AIS_ACCOUNT_BLOCKED -> {
                return generateAisResponseBody(
                        AisInterventionType.AIS_ACCOUNT_BLOCKED, true, false, false, false);
            }
            case AIS_ACCOUNT_UNBLOCKED -> {
                return generateAisResponseBody(
                        AisInterventionType.AIS_ACCOUNT_UNBLOCKED, false, false, false, false);
            }
            case AIS_FORCED_USER_PASSWORD_RESET -> {
                return generateAisResponseBody(
                        AisInterventionType.AIS_FORCED_USER_PASSWORD_RESET,
                        false,
                        true,
                        false,
                        true);
            }
            case AIS_FORCED_USER_IDENTITY_VERIFY -> {
                return generateAisResponseBody(
                        AisInterventionType.AIS_FORCED_USER_IDENTITY_VERIFY,
                        false,
                        true,
                        true,
                        false);
            }
            case AIS_FORCED_USER_PASSWORD_RESET_AND_IDENTITY_VERIFY -> {
                return generateAisResponseBody(
                        AisInterventionType.AIS_FORCED_USER_PASSWORD_RESET_AND_IDENTITY_VERIFY,
                        false,
                        true,
                        true,
                        true);
            }
        }

        throw new Exception("AisInterventionType has no corresponding response body");
    }

    private static RequestResponsePact buildRequestResponsePact(
            PactDslWithProvider builder, AisInterventionType interventionType) throws Exception {
        return builder.given(
                        String.format(
                                "test-user-id has %s interventionType", interventionType.name()))
                .given("test-user-id has no history of interventions applied to their account")
                .given(String.format("intervention updatedAt is %s", CURRENT_TIME))
                .given(String.format("intervention appliedAt is %s", CURRENT_TIME))
                .given(String.format("intervention sentAt is %s", CURRENT_TIME))
                .uponReceiving(
                        "a valid request to get a user's account interventions with userId 'test-user-id'")
                .path("/ais/" + TEST_USER_ID)
                .method("GET")
                .headers(Map.of(CONTENT_TYPE, ContentType.APPLICATION_JSON.toString()))
                .willRespondWith()
                .status(200)
                .body(getResponseBodyByIntervention(interventionType))
                .toPact();
    }

    private static DslPart generateAisResponseBody(
            AisInterventionType interventionType,
            boolean blocked,
            boolean suspended,
            boolean reproveIdentity,
            boolean resetPassword) {
        return newJsonBody(
                        body -> {
                            body.object(
                                    "intervention",
                                    intervention -> {
                                        intervention.numberType("updatedAt", CURRENT_TIME);
                                        intervention.numberType("appliedAt", CURRENT_TIME);
                                        intervention.numberType("sentAt", CURRENT_TIME);
                                        intervention.stringType(
                                                "description", interventionType.name());
                                    });
                            body.object(
                                    "state",
                                    state -> {
                                        state.booleanValue("blocked", blocked);
                                        state.booleanValue("suspended", suspended);
                                        state.booleanValue("reproveIdentity", reproveIdentity);
                                        state.booleanValue("resetPassword", resetPassword);
                                    });
                        })
                .build();
    }
}
