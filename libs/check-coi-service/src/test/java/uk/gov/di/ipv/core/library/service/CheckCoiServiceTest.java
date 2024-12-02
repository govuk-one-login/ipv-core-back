package uk.gov.di.ipv.core.library.service;

import com.fasterxml.jackson.core.JsonParser;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.ArgumentCaptor;
import org.mockito.Captor;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import uk.gov.di.ipv.core.library.auditing.AuditEvent;
import uk.gov.di.ipv.core.library.auditing.AuditEventTypes;
import uk.gov.di.ipv.core.library.auditing.extension.AuditExtensionCoiCheck;
import uk.gov.di.ipv.core.library.config.ConfigurationVariable;
import uk.gov.di.ipv.core.library.domain.ErrorResponse;
import uk.gov.di.ipv.core.library.domain.IdentityClaim;
import uk.gov.di.ipv.core.library.domain.ReverificationStatus;
import uk.gov.di.ipv.core.library.enums.CoiCheckType;
import uk.gov.di.ipv.core.library.enums.EvcsVCState;
import uk.gov.di.ipv.core.library.exception.CheckCoiException;
import uk.gov.di.ipv.core.library.exceptions.HttpResponseExceptionWithErrorBody;
import uk.gov.di.ipv.core.library.exceptions.UnknownCoiCheckTypeException;
import uk.gov.di.ipv.core.library.exceptions.VerifiableCredentialException;
import uk.gov.di.ipv.core.library.helpers.vocab.BirthDateGenerator;
import uk.gov.di.ipv.core.library.persistence.item.ClientOAuthSessionItem;
import uk.gov.di.ipv.core.library.persistence.item.IpvSessionItem;
import uk.gov.di.ipv.core.library.testhelpers.unit.LogCollector;
import uk.gov.di.ipv.core.library.verifiablecredential.service.SessionCredentialsService;
import uk.gov.di.model.NamePart;

import java.util.List;
import java.util.Optional;

import static com.nimbusds.oauth2.sdk.http.HTTPResponse.SC_SERVER_ERROR;
import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.core.StringContains.containsString;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;
import static uk.gov.di.ipv.core.library.domain.ErrorResponse.FAILED_NAME_CORRELATION;
import static uk.gov.di.ipv.core.library.domain.ErrorResponse.FAILED_TO_GET_CREDENTIAL;
import static uk.gov.di.ipv.core.library.enums.CoiCheckType.FULL_NAME_AND_DOB;
import static uk.gov.di.ipv.core.library.enums.CoiCheckType.GIVEN_OR_FAMILY_NAME_AND_DOB;
import static uk.gov.di.ipv.core.library.fixtures.VcFixtures.M1A_ADDRESS_VC;
import static uk.gov.di.ipv.core.library.fixtures.VcFixtures.M1A_EXPERIAN_FRAUD_VC;
import static uk.gov.di.ipv.core.library.helpers.vocab.NameGenerator.NamePartGenerator.createNamePart;
import static uk.gov.di.ipv.core.library.helpers.vocab.NameGenerator.createName;

@ExtendWith(MockitoExtension.class)
public class CheckCoiServiceTest {
    private static final String EVCS_ACCESS_TOKEN = "evcs-access-token";
    private static final String USER_ID = "user-id";
    private static final String IPV_SESSION_ID = "ipv-session-id";
    private static final String OPENID_SCOPE = "openid";
    private static final String REVERIFICATION_SCOPE = "reverification";

    @Mock private ConfigService mockConfigService;
    @Mock private AuditService mockAuditService;
    @Mock private SessionCredentialsService mockSessionCredentialsService;
    @Mock private UserIdentityService mockUserIdentityService;
    @Mock private EvcsService mockEvcsService;
    @Mock private IpvSessionService mockIpvSessionService;
    @InjectMocks private CheckCoiService checkCoiService;
    @Captor private ArgumentCaptor<AuditEvent> auditEventCaptor;

    @Nested
    class IsCoiCheckSuccessful {

        @Nested
        class NoErrors {
            @BeforeEach
            void setup() throws Exception {
                when(mockEvcsService.getVerifiableCredentials(
                                USER_ID, EVCS_ACCESS_TOKEN, EvcsVCState.CURRENT))
                        .thenReturn(List.of(M1A_ADDRESS_VC));
                when(mockSessionCredentialsService.getCredentials(IPV_SESSION_ID, USER_ID))
                        .thenReturn(List.of(M1A_EXPERIAN_FRAUD_VC));
                when(mockConfigService.getParameter(ConfigurationVariable.COMPONENT_ID))
                        .thenReturn("some-component-id");

                when(mockUserIdentityService.findIdentityClaim(any()))
                        .thenReturn(getMockIdentityClaim());
            }

            @Test
            void shouldReturnTrueForSuccessfulNamesAndDobCheck() throws Exception {
                // Arrange
                when(mockUserIdentityService.areNamesAndDobCorrelated(any())).thenReturn(true);

                var ipvSessionItem = new IpvSessionItem();
                ipvSessionItem.setIpvSessionId(IPV_SESSION_ID);

                var clientOAuthSessionItem =
                        ClientOAuthSessionItem.builder()
                                .scope(OPENID_SCOPE)
                                .userId(USER_ID)
                                .evcsAccessToken(EVCS_ACCESS_TOKEN)
                                .build();

                // Act
                var res =
                        checkCoiService.isCoiCheckSuccessful(
                                ipvSessionItem,
                                clientOAuthSessionItem,
                                GIVEN_OR_FAMILY_NAME_AND_DOB,
                                "device-information",
                                "ip-address");

                // Assert
                assertTrue(res);

                verify(mockAuditService, times(2)).sendAuditEvent(auditEventCaptor.capture());
                var auditEventsCaptured = auditEventCaptor.getAllValues();

                assertEquals(
                        AuditEventTypes.IPV_CONTINUITY_OF_IDENTITY_CHECK_START,
                        auditEventsCaptured.get(0).getEventName());
                assertEquals(
                        new AuditExtensionCoiCheck(GIVEN_OR_FAMILY_NAME_AND_DOB, null),
                        auditEventsCaptured.get(0).getExtensions());
                assertEquals(
                        AuditEventTypes.IPV_CONTINUITY_OF_IDENTITY_CHECK_END,
                        auditEventsCaptured.get(1).getEventName());
                assertEquals(
                        new AuditExtensionCoiCheck(GIVEN_OR_FAMILY_NAME_AND_DOB, true),
                        auditEventsCaptured.get(1).getExtensions());

                var restrictedAuditData =
                        getRestrictedAuditDataNodeFromEvent(auditEventsCaptured.get(1));
                assertTrue(restrictedAuditData.has("newName"));
                assertTrue(restrictedAuditData.has("oldName"));
                assertTrue(restrictedAuditData.has("newBirthDate"));
                assertTrue(restrictedAuditData.has("oldBirthDate"));
                assertTrue(restrictedAuditData.has("device_information"));
            }

            @Test
            void shouldReturnTrueForSuccessfulFullNameAndDobCheck() throws Exception {
                // Arrange
                when(mockUserIdentityService.areVcsCorrelated(any())).thenReturn(true);

                var ipvSessionItem = new IpvSessionItem();
                ipvSessionItem.setIpvSessionId(IPV_SESSION_ID);

                var clientOAuthSessionItem =
                        ClientOAuthSessionItem.builder()
                                .scope(OPENID_SCOPE)
                                .userId(USER_ID)
                                .evcsAccessToken(EVCS_ACCESS_TOKEN)
                                .build();

                // Act
                var res =
                        checkCoiService.isCoiCheckSuccessful(
                                ipvSessionItem,
                                clientOAuthSessionItem,
                                FULL_NAME_AND_DOB,
                                "device-information",
                                "ip-address");

                // Assert
                assertTrue(res);
                verify(mockAuditService, times(2)).sendAuditEvent(auditEventCaptor.capture());
            }

            @Test
            void shouldDoFullCheckIfReproveIdentityJourney() throws Exception {
                when(mockUserIdentityService.areVcsCorrelated(
                                List.of(M1A_ADDRESS_VC, M1A_EXPERIAN_FRAUD_VC)))
                        .thenReturn(true);
                var ipvSessionItem = new IpvSessionItem();
                ipvSessionItem.setIpvSessionId(IPV_SESSION_ID);

                var clientOAuthSessionItem =
                        ClientOAuthSessionItem.builder()
                                .scope(OPENID_SCOPE)
                                .userId(USER_ID)
                                .evcsAccessToken(EVCS_ACCESS_TOKEN)
                                .reproveIdentity(true)
                                .build();

                // Act
                var res =
                        checkCoiService.isCoiCheckSuccessful(
                                ipvSessionItem,
                                clientOAuthSessionItem,
                                GIVEN_OR_FAMILY_NAME_AND_DOB,
                                "device-information",
                                "ip-address");

                // Assert
                assertTrue(res);
                verify(mockAuditService, times(2)).sendAuditEvent(auditEventCaptor.capture());
            }

            @Test
            void
                    shouldReturnPassedForSuccessfulReverificationCheckAndSetReverificationStatusToSuccess()
                            throws Exception {
                when(mockUserIdentityService.areVcsCorrelated(any())).thenReturn(true);

                var ipvSessionItem = new IpvSessionItem();
                ipvSessionItem.setIpvSessionId(IPV_SESSION_ID);

                var clientOAuthSessionItem =
                        ClientOAuthSessionItem.builder()
                                .scope(REVERIFICATION_SCOPE)
                                .userId(USER_ID)
                                .evcsAccessToken(EVCS_ACCESS_TOKEN)
                                .build();

                // Act
                var res =
                        checkCoiService.isCoiCheckSuccessful(
                                ipvSessionItem,
                                clientOAuthSessionItem,
                                FULL_NAME_AND_DOB,
                                "device-information",
                                "ip-address");

                // Assert
                assertTrue(res);
                assertEquals(
                        ReverificationStatus.SUCCESS, ipvSessionItem.getReverificationStatus());

                verify(mockAuditService, times(2)).sendAuditEvent(auditEventCaptor.capture());
                verify(mockIpvSessionService, times(1)).updateIpvSession(ipvSessionItem);
            }

            @Test
            void shouldSendOnlyDeviceInformationInRestrictedDataIfNoIdentityClaimsFound()
                    throws Exception {
                when(mockUserIdentityService.areNamesAndDobCorrelated(any())).thenReturn(true);
                when(mockUserIdentityService.findIdentityClaim(any())).thenReturn(Optional.empty());

                var ipvSessionItem = new IpvSessionItem();
                ipvSessionItem.setIpvSessionId(IPV_SESSION_ID);

                var clientOAuthSessionItem =
                        ClientOAuthSessionItem.builder()
                                .scope(OPENID_SCOPE)
                                .userId(USER_ID)
                                .evcsAccessToken(EVCS_ACCESS_TOKEN)
                                .build();

                // Act
                var res =
                        checkCoiService.isCoiCheckSuccessful(
                                ipvSessionItem,
                                clientOAuthSessionItem,
                                GIVEN_OR_FAMILY_NAME_AND_DOB,
                                "device-information",
                                "ip-address");

                // Assert
                assertTrue(res);

                verify(mockAuditService, times(2)).sendAuditEvent(auditEventCaptor.capture());
                var auditEventsCaptured = auditEventCaptor.getAllValues();

                assertEquals(
                        AuditEventTypes.IPV_CONTINUITY_OF_IDENTITY_CHECK_START,
                        auditEventsCaptured.get(0).getEventName());
                assertEquals(
                        new AuditExtensionCoiCheck(GIVEN_OR_FAMILY_NAME_AND_DOB, null),
                        auditEventsCaptured.get(0).getExtensions());
                assertEquals(
                        AuditEventTypes.IPV_CONTINUITY_OF_IDENTITY_CHECK_END,
                        auditEventsCaptured.get(1).getEventName());
                assertEquals(
                        new AuditExtensionCoiCheck(GIVEN_OR_FAMILY_NAME_AND_DOB, true),
                        auditEventsCaptured.get(1).getExtensions());

                var restrictedAuditData =
                        getRestrictedAuditDataNodeFromEvent(auditEventsCaptured.get(1));
                assertFalse(restrictedAuditData.has("newName"));
                assertFalse(restrictedAuditData.has("oldName"));
                assertFalse(restrictedAuditData.has("newBirthDate"));
                assertFalse(restrictedAuditData.has("oldBirthDate"));
                assertTrue(restrictedAuditData.has("device_information"));
            }

            @Test
            void shouldReturnFalseForFailedGivenNamesAndDobCheck() throws Exception {
                // Arrange
                when(mockUserIdentityService.areNamesAndDobCorrelated(any())).thenReturn(false);

                var ipvSessionItem = new IpvSessionItem();
                ipvSessionItem.setIpvSessionId(IPV_SESSION_ID);

                var clientOAuthSessionItem =
                        ClientOAuthSessionItem.builder()
                                .scope(OPENID_SCOPE)
                                .userId(USER_ID)
                                .evcsAccessToken(EVCS_ACCESS_TOKEN)
                                .build();

                // Act
                var res =
                        checkCoiService.isCoiCheckSuccessful(
                                ipvSessionItem,
                                clientOAuthSessionItem,
                                GIVEN_OR_FAMILY_NAME_AND_DOB,
                                "device-information",
                                "ip-address");

                // Assert
                assertFalse(res);

                verify(mockAuditService, times(2)).sendAuditEvent(auditEventCaptor.capture());
                var auditEventsCaptured = auditEventCaptor.getAllValues();

                assertEquals(
                        AuditEventTypes.IPV_CONTINUITY_OF_IDENTITY_CHECK_START,
                        auditEventsCaptured.get(0).getEventName());
                assertEquals(
                        new AuditExtensionCoiCheck(GIVEN_OR_FAMILY_NAME_AND_DOB, null),
                        auditEventsCaptured.get(0).getExtensions());
                assertEquals(
                        AuditEventTypes.IPV_CONTINUITY_OF_IDENTITY_CHECK_END,
                        auditEventsCaptured.get(1).getEventName());
                assertEquals(
                        new AuditExtensionCoiCheck(GIVEN_OR_FAMILY_NAME_AND_DOB, false),
                        auditEventsCaptured.get(1).getExtensions());

                var restrictedAuditData =
                        getRestrictedAuditDataNodeFromEvent(auditEventsCaptured.get(1));
                assertTrue(restrictedAuditData.has("newName"));
                assertTrue(restrictedAuditData.has("oldName"));
                assertTrue(restrictedAuditData.has("newBirthDate"));
                assertTrue(restrictedAuditData.has("oldBirthDate"));
                assertTrue(restrictedAuditData.has("device_information"));
            }

            @Test
            void shouldReturnFalseForFailedFullNameAndDobCheck() throws Exception {
                // Arrange
                when(mockUserIdentityService.areVcsCorrelated(any())).thenReturn(false);

                var ipvSessionItem = new IpvSessionItem();
                ipvSessionItem.setIpvSessionId(IPV_SESSION_ID);

                var clientOAuthSessionItem =
                        ClientOAuthSessionItem.builder()
                                .scope(OPENID_SCOPE)
                                .userId(USER_ID)
                                .evcsAccessToken(EVCS_ACCESS_TOKEN)
                                .build();

                // Act
                var res =
                        checkCoiService.isCoiCheckSuccessful(
                                ipvSessionItem,
                                clientOAuthSessionItem,
                                FULL_NAME_AND_DOB,
                                "device-information",
                                "ip-address");

                // Assert
                assertFalse(res);

                verify(mockAuditService, times(2)).sendAuditEvent(auditEventCaptor.capture());
                var auditEventsCaptured = auditEventCaptor.getAllValues();

                assertEquals(
                        AuditEventTypes.IPV_CONTINUITY_OF_IDENTITY_CHECK_END,
                        auditEventsCaptured.get(1).getEventName());
                assertEquals(
                        new AuditExtensionCoiCheck(FULL_NAME_AND_DOB, false),
                        auditEventsCaptured.get(1).getExtensions());
            }

            @Test
            void shouldReturnFalseForFailedReverificationCheckAndReverificationStatusSetToFailed()
                    throws Exception {
                // Arrange
                when(mockUserIdentityService.areVcsCorrelated(any())).thenReturn(false);

                var ipvSessionItem = new IpvSessionItem();
                ipvSessionItem.setIpvSessionId(IPV_SESSION_ID);

                var clientOAuthSessionItem =
                        ClientOAuthSessionItem.builder()
                                .scope(REVERIFICATION_SCOPE)
                                .userId(USER_ID)
                                .evcsAccessToken(EVCS_ACCESS_TOKEN)
                                .build();

                // Act
                var res =
                        checkCoiService.isCoiCheckSuccessful(
                                ipvSessionItem,
                                clientOAuthSessionItem,
                                FULL_NAME_AND_DOB,
                                "device-information",
                                "ip-address");

                // Assert
                assertFalse(res);

                verify(mockAuditService, times(2)).sendAuditEvent(auditEventCaptor.capture());
                var auditEventsCaptured = auditEventCaptor.getAllValues();

                assertEquals(
                        AuditEventTypes.IPV_CONTINUITY_OF_IDENTITY_CHECK_END,
                        auditEventsCaptured.get(1).getEventName());
                assertEquals(
                        new AuditExtensionCoiCheck(FULL_NAME_AND_DOB, false),
                        auditEventsCaptured.get(1).getExtensions());
            }
        }

        @Nested
        class ThrowsErrors {
            private final ClientOAuthSessionItem clientOAuthSessionItem =
                    ClientOAuthSessionItem.builder()
                            .scope(OPENID_SCOPE)
                            .userId(USER_ID)
                            .evcsAccessToken(EVCS_ACCESS_TOKEN)
                            .build();

            @Test
            void shouldThrowIfNameCorrelationCheckThrowsHttpResponseException() throws Exception {
                // Arrange
                when(mockUserIdentityService.areNamesAndDobCorrelated(any()))
                        .thenThrow(
                                new HttpResponseExceptionWithErrorBody(
                                        SC_SERVER_ERROR, FAILED_NAME_CORRELATION));

                var ipvSessionItem = new IpvSessionItem();
                ipvSessionItem.setIpvSessionId(IPV_SESSION_ID);

                // Act/Assert
                assertThrows(
                        CheckCoiException.class,
                        () ->
                                checkCoiService.isCoiCheckSuccessful(
                                        ipvSessionItem,
                                        clientOAuthSessionItem,
                                        GIVEN_OR_FAMILY_NAME_AND_DOB,
                                        "device-information",
                                        "ip-address"));
            }

            @Test
            void shouldThrowIfAreVcsCorrelatedCheckThrowsHttpResponseException() throws Exception {
                // Arrange
                when(mockUserIdentityService.areVcsCorrelated(any()))
                        .thenThrow(
                                new HttpResponseExceptionWithErrorBody(
                                        SC_SERVER_ERROR, FAILED_NAME_CORRELATION));

                var ipvSessionItem = new IpvSessionItem();
                ipvSessionItem.setIpvSessionId(IPV_SESSION_ID);

                // Act/Assert
                assertThrows(
                        CheckCoiException.class,
                        () ->
                                checkCoiService.isCoiCheckSuccessful(
                                        ipvSessionItem,
                                        clientOAuthSessionItem,
                                        FULL_NAME_AND_DOB,
                                        "device-information",
                                        "ip-address"));
            }

            @Test
            void shouldThrowIfGettingSessionCredentialsThrows() throws Exception {
                // Arrange
                when(mockSessionCredentialsService.getCredentials(IPV_SESSION_ID, USER_ID))
                        .thenThrow(
                                new VerifiableCredentialException(
                                        SC_SERVER_ERROR, FAILED_TO_GET_CREDENTIAL));

                var ipvSessionItem = new IpvSessionItem();
                ipvSessionItem.setIpvSessionId(IPV_SESSION_ID);

                // Act/Assert
                assertThrows(
                        CheckCoiException.class,
                        () ->
                                checkCoiService.isCoiCheckSuccessful(
                                        ipvSessionItem,
                                        clientOAuthSessionItem,
                                        GIVEN_OR_FAMILY_NAME_AND_DOB,
                                        "device-information",
                                        "ip-address"));
            }

            @Test
            void shouldThrowIfFindIdentityClaimThrowsHttpResponseException() throws Exception {
                when(mockUserIdentityService.areNamesAndDobCorrelated(
                                List.of(M1A_ADDRESS_VC, M1A_EXPERIAN_FRAUD_VC)))
                        .thenReturn(true);
                when(mockUserIdentityService.findIdentityClaim(any()))
                        .thenThrow(
                                new HttpResponseExceptionWithErrorBody(
                                        500, ErrorResponse.FAILED_TO_GENERATE_IDENTITY_CLAIM));

                var ipvSessionItem = new IpvSessionItem();
                ipvSessionItem.setIpvSessionId(IPV_SESSION_ID);

                // Act/Assert
                assertThrows(
                        CheckCoiException.class,
                        () ->
                                checkCoiService.isCoiCheckSuccessful(
                                        ipvSessionItem,
                                        clientOAuthSessionItem,
                                        GIVEN_OR_FAMILY_NAME_AND_DOB,
                                        "device-information",
                                        "ip-address"));
            }

            @Test
            void shouldLogRuntimeExceptionsAndRethrow() throws Exception {
                // Arrange
                when(mockUserIdentityService.areNamesAndDobCorrelated(any()))
                        .thenThrow(new RuntimeException("Test error"));

                var ipvSessionItem = new IpvSessionItem();
                ipvSessionItem.setIpvSessionId(IPV_SESSION_ID);

                var logCollector = LogCollector.getLogCollectorFor(CheckCoiService.class);

                // Act
                var thrown =
                        assertThrows(
                                CheckCoiException.class,
                                () ->
                                        checkCoiService.isCoiCheckSuccessful(
                                                ipvSessionItem,
                                                clientOAuthSessionItem,
                                                GIVEN_OR_FAMILY_NAME_AND_DOB,
                                                "device-information",
                                                "ip-address"),
                                "Expected handleRequest() to throw, but it didn't");

                // Assert
                assertEquals("Unhandled exception: Test error", thrown.getMessage());

                var logMessage = logCollector.getLogMessages().get(0);
                assertThat(logMessage, containsString("Unhandled exception"));
                assertThat(logMessage, containsString("Test error"));
            }
        }

        private Optional<IdentityClaim> getMockIdentityClaim() {
            var mockNameParts =
                    createNamePart("Kenneth Decerqueira", NamePart.NamePartType.FAMILY_NAME);
            var mockBirthDate = BirthDateGenerator.createBirthDate("1965-07-08");
            return Optional.of(
                    new IdentityClaim(
                            List.of(createName(List.of(mockNameParts))), List.of(mockBirthDate)));
        }
    }

    @Nested
    class ParseAndValidateCoiCheckType {
        @Test
        void shouldReturnParsedCheckTypeIfValid() throws Exception {
            // Act
            var res =
                    CheckCoiService.parseAndValidateCoiCheckType(
                            "GIVEN_OR_FAMILY_NAME_AND_DOB", new ClientOAuthSessionItem());

            // Assert
            assertEquals(CoiCheckType.GIVEN_OR_FAMILY_NAME_AND_DOB, res);
        }

        @Test
        void shouldThrowIfPassedInvalidCheckType() {
            assertThrows(
                    UnknownCoiCheckTypeException.class,
                    () ->
                            CheckCoiService.parseAndValidateCoiCheckType(
                                    "invalid-check-type", new ClientOAuthSessionItem()));
        }

        @Test
        void shouldReturnFullNameWithAllowanceAndDobCheckTypeIfReproveIdentityIsSet()
                throws Exception {
            // Arrange
            var clientOAuthSessionItem =
                    ClientOAuthSessionItem.builder().reproveIdentity(true).build();

            // Act
            var res =
                    CheckCoiService.parseAndValidateCoiCheckType(
                            "GIVEN_OR_FAMILY_NAME_AND_DOB", clientOAuthSessionItem);

            // Assert
            assertEquals(CoiCheckType.FULL_NAME_AND_DOB, res);
        }
    }

    private JsonNode getRestrictedAuditDataNodeFromEvent(AuditEvent auditEvent) throws Exception {
        var coiCheckEndAuditEvent = getJsonNodeForAuditEvent(auditEvent);
        return coiCheckEndAuditEvent.get("restricted");
    }

    private JsonNode getJsonNodeForAuditEvent(AuditEvent object) throws Exception {
        ObjectMapper mapper = new ObjectMapper();
        String json = mapper.writeValueAsString(object);
        JsonParser parser = mapper.createParser(json);
        return mapper.readTree(parser);
    }
}
