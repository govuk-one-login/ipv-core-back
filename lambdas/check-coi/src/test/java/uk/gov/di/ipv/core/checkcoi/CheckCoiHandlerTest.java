package uk.gov.di.ipv.core.checkcoi;

import com.amazonaws.services.lambda.runtime.Context;
import com.fasterxml.jackson.core.JsonParser;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.ArgumentCaptor;
import org.mockito.Captor;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.mockito.junit.jupiter.MockitoSettings;
import uk.gov.di.ipv.core.library.auditing.AuditEvent;
import uk.gov.di.ipv.core.library.auditing.AuditEventTypes;
import uk.gov.di.ipv.core.library.auditing.extension.AuditExtensionCoiCheck;
import uk.gov.di.ipv.core.library.domain.ErrorResponse;
import uk.gov.di.ipv.core.library.domain.IdentityClaim;
import uk.gov.di.ipv.core.library.domain.Name;
import uk.gov.di.ipv.core.library.domain.NameParts;
import uk.gov.di.ipv.core.library.domain.ProcessRequest;
import uk.gov.di.ipv.core.library.domain.ReverificationStatus;
import uk.gov.di.ipv.core.library.domain.ScopeConstants;
import uk.gov.di.ipv.core.library.domain.VerifiableCredential;
import uk.gov.di.ipv.core.library.enums.CoiCheckType;
import uk.gov.di.ipv.core.library.enums.EvcsVCState;
import uk.gov.di.ipv.core.library.exception.EvcsServiceException;
import uk.gov.di.ipv.core.library.exceptions.CredentialParseException;
import uk.gov.di.ipv.core.library.exceptions.HttpResponseExceptionWithErrorBody;
import uk.gov.di.ipv.core.library.exceptions.SqsException;
import uk.gov.di.ipv.core.library.exceptions.VerifiableCredentialException;
import uk.gov.di.ipv.core.library.helpers.BirthDateHelper;
import uk.gov.di.ipv.core.library.persistence.item.ClientOAuthSessionItem;
import uk.gov.di.ipv.core.library.persistence.item.IpvSessionItem;
import uk.gov.di.ipv.core.library.service.AuditService;
import uk.gov.di.ipv.core.library.service.ClientOAuthSessionDetailsService;
import uk.gov.di.ipv.core.library.service.ConfigService;
import uk.gov.di.ipv.core.library.service.EvcsService;
import uk.gov.di.ipv.core.library.service.IpvSessionService;
import uk.gov.di.ipv.core.library.service.UserIdentityService;
import uk.gov.di.ipv.core.library.verifiablecredential.service.SessionCredentialsService;
import uk.gov.di.ipv.core.library.verifiablecredential.service.VerifiableCredentialService;

import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.Optional;

import static com.nimbusds.oauth2.sdk.http.HTTPResponse.SC_SERVER_ERROR;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;
import static org.mockito.quality.Strictness.LENIENT;
import static uk.gov.di.ipv.core.library.config.CoreFeatureFlag.EVCS_READ_ENABLED;
import static uk.gov.di.ipv.core.library.domain.ErrorResponse.FAILED_NAME_CORRELATION;
import static uk.gov.di.ipv.core.library.domain.ErrorResponse.FAILED_TO_GENERATE_IDENTIY_CLAIM;
import static uk.gov.di.ipv.core.library.domain.ErrorResponse.FAILED_TO_GET_CREDENTIAL;
import static uk.gov.di.ipv.core.library.domain.ErrorResponse.MISSING_CHECK_TYPE;
import static uk.gov.di.ipv.core.library.domain.ErrorResponse.MISSING_IPV_SESSION_ID;
import static uk.gov.di.ipv.core.library.domain.ErrorResponse.UNKNOWN_CHECK_TYPE;
import static uk.gov.di.ipv.core.library.enums.CoiCheckType.FAMILY_NAME_AND_DOB;
import static uk.gov.di.ipv.core.library.enums.CoiCheckType.FULL_NAME_AND_DOB;
import static uk.gov.di.ipv.core.library.enums.CoiCheckType.GIVEN_NAMES_AND_DOB;
import static uk.gov.di.ipv.core.library.fixtures.VcFixtures.M1A_ADDRESS_VC;
import static uk.gov.di.ipv.core.library.fixtures.VcFixtures.M1A_EXPERIAN_FRAUD_VC;
import static uk.gov.di.ipv.core.library.journeyuris.JourneyUris.JOURNEY_COI_CHECK_FAILED_PATH;
import static uk.gov.di.ipv.core.library.journeyuris.JourneyUris.JOURNEY_COI_CHECK_PASSED_PATH;
import static uk.gov.di.ipv.core.library.journeyuris.JourneyUris.JOURNEY_ERROR_PATH;

@ExtendWith(MockitoExtension.class)
class CheckCoiHandlerTest {
    private static final String IPV_SESSION_ID = "ipv-session-id";
    private static final String CLIENT_SESSION_ID = "client-session-id";
    private static final String USER_ID = "user-id";
    private static final String DEVICE_INFORMATION = "dummy-device-information";
    @Mock private ConfigService mockConfigService;
    @Mock private AuditService mockAuditService;
    @Mock private IpvSessionService mockIpvSessionService;
    @Mock private ClientOAuthSessionDetailsService mockClientSessionService;
    @Mock private VerifiableCredentialService mockVerifiableCredentialService;
    @Mock private SessionCredentialsService mockSessionCredentialService;
    @Mock private UserIdentityService mockUserIdentityService;
    @Mock private EvcsService mockEvcsService;
    @Mock private Context mockContext;
    @Mock private IpvSessionItem mockIpvSessionItem;
    @Mock private ClientOAuthSessionItem mockClientSessionItem;
    @InjectMocks CheckCoiHandler checkCoiHandler;
    @Captor private ArgumentCaptor<AuditEvent> auditEventCaptor;

    @BeforeEach
    void setup() throws Exception {
        when(mockIpvSessionService.getIpvSession(IPV_SESSION_ID)).thenReturn(mockIpvSessionItem);
        when(mockIpvSessionItem.getIpvSessionId()).thenReturn(IPV_SESSION_ID);
        when(mockIpvSessionItem.getClientOAuthSessionId()).thenReturn(CLIENT_SESSION_ID);

        when(mockClientSessionService.getClientOAuthSession(CLIENT_SESSION_ID))
                .thenReturn(mockClientSessionItem);
        when(mockClientSessionItem.getUserId()).thenReturn(USER_ID);

        // The actual VCs here are irrelevant as we're mocking the user identity service
        when(mockVerifiableCredentialService.getVcs(USER_ID)).thenReturn(List.of(M1A_ADDRESS_VC));
        when(mockSessionCredentialService.getCredentials(IPV_SESSION_ID, USER_ID))
                .thenReturn(List.of(M1A_EXPERIAN_FRAUD_VC));
    }

    @Nested
    class SuccessAndFailChecks {
        @BeforeEach
        void setup() throws Exception {
            when(mockUserIdentityService.findIdentityClaim(any()))
                    .thenReturn(getMockIdentityClaim());
        }

        private Optional<IdentityClaim> getMockIdentityClaim() {
            var mockNameParts = new NameParts("Kenneth Decerqueira", "full-name");
            var mockBirthDate = BirthDateHelper.createBirthDate("1965-07-08");
            return Optional.of(
                    new IdentityClaim(
                            List.of(new Name(List.of(mockNameParts))), List.of(mockBirthDate)));
        }

        @Nested
        @DisplayName("Successful checks")
        class SuccessfulChecks {
            @Test
            void shouldReturnPassedForSuccessfulGivenNamesAndDobCheck() throws Exception {
                when(mockUserIdentityService.areGivenNamesAndDobCorrelated(
                                List.of(M1A_ADDRESS_VC, M1A_EXPERIAN_FRAUD_VC)))
                        .thenReturn(true);
                when(mockClientSessionItem.getScopeClaims())
                        .thenReturn(List.of(ScopeConstants.OPENID));

                var request =
                        ProcessRequest.processRequestBuilder()
                                .ipvSessionId(IPV_SESSION_ID)
                                .lambdaInput(Map.of("checkType", GIVEN_NAMES_AND_DOB.name()))
                                .build();

                var responseMap = checkCoiHandler.handleRequest(request, mockContext);

                assertEquals(JOURNEY_COI_CHECK_PASSED_PATH, responseMap.get("journey"));
                verify(mockAuditService, times(2)).sendAuditEvent(auditEventCaptor.capture());
                var auditEventsCaptured = auditEventCaptor.getAllValues();

                assertEquals(
                        AuditEventTypes.IPV_CONTINUITY_OF_IDENTITY_CHECK_START,
                        auditEventsCaptured.get(0).getEventName());
                assertEquals(
                        new AuditExtensionCoiCheck(GIVEN_NAMES_AND_DOB, null),
                        auditEventsCaptured.get(0).getExtensions());
                assertEquals(
                        AuditEventTypes.IPV_CONTINUITY_OF_IDENTITY_CHECK_END,
                        auditEventsCaptured.get(1).getEventName());
                assertEquals(
                        new AuditExtensionCoiCheck(GIVEN_NAMES_AND_DOB, true),
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
            void shouldReturnPassedForSuccessfulFamilyNameAndDobCheck() throws Exception {
                when(mockUserIdentityService.areFamilyNameAndDobCorrelatedForCoiCheck(
                                List.of(M1A_ADDRESS_VC, M1A_EXPERIAN_FRAUD_VC)))
                        .thenReturn(true);
                when(mockClientSessionItem.getScopeClaims())
                        .thenReturn(List.of(ScopeConstants.OPENID));

                var request =
                        ProcessRequest.processRequestBuilder()
                                .ipvSessionId(IPV_SESSION_ID)
                                .lambdaInput(Map.of("checkType", FAMILY_NAME_AND_DOB.name()))
                                .build();

                var responseMap = checkCoiHandler.handleRequest(request, mockContext);

                assertEquals(JOURNEY_COI_CHECK_PASSED_PATH, responseMap.get("journey"));
                verify(mockAuditService, times(2)).sendAuditEvent(auditEventCaptor.capture());
                var auditEventsCaptured = auditEventCaptor.getAllValues();

                assertEquals(
                        AuditEventTypes.IPV_CONTINUITY_OF_IDENTITY_CHECK_START,
                        auditEventsCaptured.get(0).getEventName());
                assertEquals(
                        new AuditExtensionCoiCheck(FAMILY_NAME_AND_DOB, null),
                        auditEventsCaptured.get(0).getExtensions());
                assertEquals(
                        AuditEventTypes.IPV_CONTINUITY_OF_IDENTITY_CHECK_END,
                        auditEventsCaptured.get(1).getEventName());
                assertEquals(
                        new AuditExtensionCoiCheck(FAMILY_NAME_AND_DOB, true),
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
            void shouldReturnPassedForSuccessfulFullNameAndDobCheck() throws Exception {
                when(mockUserIdentityService.areVcsCorrelated(
                                List.of(M1A_ADDRESS_VC, M1A_EXPERIAN_FRAUD_VC)))
                        .thenReturn(true);
                when(mockClientSessionItem.getScopeClaims())
                        .thenReturn(List.of(ScopeConstants.OPENID));

                var request =
                        ProcessRequest.processRequestBuilder()
                                .ipvSessionId(IPV_SESSION_ID)
                                .lambdaInput(Map.of("checkType", FULL_NAME_AND_DOB.name()))
                                .build();

                var responseMap = checkCoiHandler.handleRequest(request, mockContext);

                assertEquals(JOURNEY_COI_CHECK_PASSED_PATH, responseMap.get("journey"));
                verify(mockAuditService, times(2)).sendAuditEvent(auditEventCaptor.capture());
                var auditEventsCaptured = auditEventCaptor.getAllValues();

                assertEquals(
                        AuditEventTypes.IPV_CONTINUITY_OF_IDENTITY_CHECK_START,
                        auditEventsCaptured.get(0).getEventName());
                assertEquals(
                        new AuditExtensionCoiCheck(CoiCheckType.FULL_NAME_AND_DOB, null),
                        auditEventsCaptured.get(0).getExtensions());
                assertEquals(
                        AuditEventTypes.IPV_CONTINUITY_OF_IDENTITY_CHECK_END,
                        auditEventsCaptured.get(1).getEventName());
                assertEquals(
                        new AuditExtensionCoiCheck(CoiCheckType.FULL_NAME_AND_DOB, true),
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
            @MockitoSettings(strictness = LENIENT)
            void shouldUseEvcsServiceWhenEnabled()
                    throws HttpResponseExceptionWithErrorBody, CredentialParseException,
                            EvcsServiceException {

                when(mockConfigService.enabled(EVCS_READ_ENABLED)).thenReturn(true);
                when(mockUserIdentityService.areVcsCorrelated(
                                List.of(M1A_ADDRESS_VC, M1A_EXPERIAN_FRAUD_VC)))
                        .thenReturn(true);
                when(mockClientSessionItem.getScopeClaims())
                        .thenReturn(List.of(ScopeConstants.OPENID));

                when(mockEvcsService.getVerifiableCredentials(any(), any(), any(EvcsVCState.class)))
                        .thenReturn(List.of(M1A_ADDRESS_VC));

                var request =
                        ProcessRequest.processRequestBuilder()
                                .ipvSessionId(IPV_SESSION_ID)
                                .lambdaInput(Map.of("checkType", FULL_NAME_AND_DOB.name()))
                                .build();

                checkCoiHandler.handleRequest(request, mockContext);

                verify(mockEvcsService, times(1))
                        .getVerifiableCredentials(USER_ID, null, EvcsVCState.CURRENT);
                verify(mockVerifiableCredentialService, never()).getVcs(USER_ID);
            }

            @Test
            void shouldUseVcStoreWhenEvcsEnabledAndReturnsEmpty()
                    throws HttpResponseExceptionWithErrorBody, CredentialParseException,
                            EvcsServiceException {

                when(mockConfigService.enabled(EVCS_READ_ENABLED)).thenReturn(true);
                when(mockUserIdentityService.areVcsCorrelated(
                                List.of(M1A_ADDRESS_VC, M1A_EXPERIAN_FRAUD_VC)))
                        .thenReturn(true);
                when(mockClientSessionItem.getScopeClaims())
                        .thenReturn(List.of(ScopeConstants.OPENID));
                when(mockEvcsService.getVerifiableCredentials(any(), any(), any(EvcsVCState.class)))
                        .thenReturn(new ArrayList<VerifiableCredential>());

                var request =
                        ProcessRequest.processRequestBuilder()
                                .ipvSessionId(IPV_SESSION_ID)
                                .lambdaInput(Map.of("checkType", FULL_NAME_AND_DOB.name()))
                                .build();

                checkCoiHandler.handleRequest(request, mockContext);

                verify(mockEvcsService, times(1))
                        .getVerifiableCredentials(USER_ID, null, EvcsVCState.CURRENT);
                verify(mockVerifiableCredentialService, times(1)).getVcs(USER_ID);
            }

            void
                    shouldReturnPassedForSuccessfulReverificationCheckAndSetReverificationStatusToSuccess()
                            throws Exception {
                when(mockUserIdentityService.areVcsCorrelated(
                                List.of(M1A_ADDRESS_VC, M1A_EXPERIAN_FRAUD_VC)))
                        .thenReturn(true);
                when(mockClientSessionItem.getScopeClaims())
                        .thenReturn(List.of(ScopeConstants.REVERIFICATION));

                var request =
                        ProcessRequest.processRequestBuilder()
                                .ipvSessionId(IPV_SESSION_ID)
                                .lambdaInput(Map.of("checkType", FULL_NAME_AND_DOB.name()))
                                .build();

                var responseMap = checkCoiHandler.handleRequest(request, mockContext);

                assertEquals(JOURNEY_COI_CHECK_PASSED_PATH, responseMap.get("journey"));
                verify(mockIpvSessionItem).setReverificationStatus(ReverificationStatus.SUCCESS);
                verify(mockAuditService, times(2)).sendAuditEvent(auditEventCaptor.capture());

                var auditEventsCaptured = auditEventCaptor.getAllValues();

                assertEquals(
                        AuditEventTypes.IPV_CONTINUITY_OF_IDENTITY_CHECK_START,
                        auditEventsCaptured.get(0).getEventName());
                assertEquals(
                        new AuditExtensionCoiCheck(CoiCheckType.FULL_NAME_AND_DOB, null),
                        auditEventsCaptured.get(0).getExtensions());
                assertEquals(
                        AuditEventTypes.IPV_CONTINUITY_OF_IDENTITY_CHECK_END,
                        auditEventsCaptured.get(1).getEventName());
                assertEquals(
                        new AuditExtensionCoiCheck(CoiCheckType.FULL_NAME_AND_DOB, true),
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
            void shouldSendOnlyDeviceInformationInRestrictedDataIfNoIdentityClaimsFound()
                    throws Exception {
                when(mockUserIdentityService.areVcsCorrelated(
                                List.of(M1A_ADDRESS_VC, M1A_EXPERIAN_FRAUD_VC)))
                        .thenReturn(true);
                when(mockClientSessionItem.getScopeClaims())
                        .thenReturn(List.of(ScopeConstants.OPENID));
                when(mockUserIdentityService.findIdentityClaim(any())).thenReturn(Optional.empty());

                var request =
                        ProcessRequest.processRequestBuilder()
                                .ipvSessionId(IPV_SESSION_ID)
                                .lambdaInput(Map.of("checkType", FULL_NAME_AND_DOB.name()))
                                .build();

                var responseMap = checkCoiHandler.handleRequest(request, mockContext);

                assertEquals(JOURNEY_COI_CHECK_PASSED_PATH, responseMap.get("journey"));
                verify(mockAuditService, times(2)).sendAuditEvent(auditEventCaptor.capture());
                var auditEventsCaptured = auditEventCaptor.getAllValues();

                assertEquals(
                        AuditEventTypes.IPV_CONTINUITY_OF_IDENTITY_CHECK_START,
                        auditEventsCaptured.get(0).getEventName());
                assertEquals(
                        new AuditExtensionCoiCheck(CoiCheckType.FULL_NAME_AND_DOB, null),
                        auditEventsCaptured.get(0).getExtensions());
                assertEquals(
                        AuditEventTypes.IPV_CONTINUITY_OF_IDENTITY_CHECK_END,
                        auditEventsCaptured.get(1).getEventName());
                assertEquals(
                        new AuditExtensionCoiCheck(CoiCheckType.FULL_NAME_AND_DOB, true),
                        auditEventsCaptured.get(1).getExtensions());

                var restrictedAuditData =
                        getRestrictedAuditDataNodeFromEvent(auditEventsCaptured.get(1));
                assertFalse(restrictedAuditData.has("newName"));
                assertFalse(restrictedAuditData.has("oldName"));
                assertFalse(restrictedAuditData.has("newBirthDate"));
                assertFalse(restrictedAuditData.has("oldBirthDate"));
                assertTrue(restrictedAuditData.has("device_information"));
            }
        }

        @Nested
        @DisplayName("Failed checks")
        class FailedChecks {
            @Test
            void shouldReturnFailedForFailedGivenNamesAndDobCheck() throws Exception {
                when(mockUserIdentityService.areGivenNamesAndDobCorrelated(
                                List.of(M1A_ADDRESS_VC, M1A_EXPERIAN_FRAUD_VC)))
                        .thenReturn(false);
                when(mockClientSessionItem.getScopeClaims())
                        .thenReturn(List.of(ScopeConstants.OPENID));

                var request =
                        ProcessRequest.processRequestBuilder()
                                .ipvSessionId(IPV_SESSION_ID)
                                .lambdaInput(Map.of("checkType", GIVEN_NAMES_AND_DOB.name()))
                                .build();

                var responseMap = checkCoiHandler.handleRequest(request, mockContext);

                assertEquals(JOURNEY_COI_CHECK_FAILED_PATH, responseMap.get("journey"));
                verify(mockAuditService, times(2)).sendAuditEvent(auditEventCaptor.capture());
                var auditEventsCaptured = auditEventCaptor.getAllValues();

                assertEquals(
                        AuditEventTypes.IPV_CONTINUITY_OF_IDENTITY_CHECK_START,
                        auditEventsCaptured.get(0).getEventName());
                assertEquals(
                        new AuditExtensionCoiCheck(GIVEN_NAMES_AND_DOB, null),
                        auditEventsCaptured.get(0).getExtensions());
                assertEquals(
                        AuditEventTypes.IPV_CONTINUITY_OF_IDENTITY_CHECK_END,
                        auditEventsCaptured.get(1).getEventName());
                assertEquals(
                        new AuditExtensionCoiCheck(GIVEN_NAMES_AND_DOB, false),
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
            void shouldReturnFailedForFailedFamilyNameAndDobCheck() throws Exception {
                when(mockUserIdentityService.areFamilyNameAndDobCorrelatedForCoiCheck(
                                List.of(M1A_ADDRESS_VC, M1A_EXPERIAN_FRAUD_VC)))
                        .thenReturn(false);
                when(mockClientSessionItem.getScopeClaims())
                        .thenReturn(List.of(ScopeConstants.OPENID));

                var request =
                        ProcessRequest.processRequestBuilder()
                                .ipvSessionId(IPV_SESSION_ID)
                                .lambdaInput(Map.of("checkType", FAMILY_NAME_AND_DOB.name()))
                                .deviceInformation(DEVICE_INFORMATION)
                                .build();

                var responseMap = checkCoiHandler.handleRequest(request, mockContext);

                assertEquals(JOURNEY_COI_CHECK_FAILED_PATH, responseMap.get("journey"));
                verify(mockAuditService, times(2)).sendAuditEvent(auditEventCaptor.capture());
                var auditEventsCaptured = auditEventCaptor.getAllValues();

                assertEquals(
                        AuditEventTypes.IPV_CONTINUITY_OF_IDENTITY_CHECK_START,
                        auditEventsCaptured.get(0).getEventName());
                assertEquals(
                        new AuditExtensionCoiCheck(FAMILY_NAME_AND_DOB, null),
                        auditEventsCaptured.get(0).getExtensions());
                assertEquals(
                        AuditEventTypes.IPV_CONTINUITY_OF_IDENTITY_CHECK_END,
                        auditEventsCaptured.get(1).getEventName());
                assertEquals(
                        new AuditExtensionCoiCheck(FAMILY_NAME_AND_DOB, false),
                        auditEventsCaptured.get(1).getExtensions());
            }

            @Test
            void shouldReturnFailedForFailedReverificationCheckandReverificationStatusSetToFailed()
                    throws Exception {
                when(mockUserIdentityService.areVcsCorrelated(
                                List.of(M1A_ADDRESS_VC, M1A_EXPERIAN_FRAUD_VC)))
                        .thenReturn(false);
                when(mockClientSessionItem.getScopeClaims())
                        .thenReturn(List.of(ScopeConstants.REVERIFICATION));

                var request =
                        ProcessRequest.processRequestBuilder()
                                .ipvSessionId(IPV_SESSION_ID)
                                .lambdaInput(Map.of("checkType", FULL_NAME_AND_DOB.name()))
                                .build();

                var responseMap = checkCoiHandler.handleRequest(request, mockContext);

                assertEquals(JOURNEY_COI_CHECK_FAILED_PATH, responseMap.get("journey"));
                verify(mockIpvSessionItem).setReverificationStatus(ReverificationStatus.FAILED);
                verify(mockAuditService, times(2)).sendAuditEvent(auditEventCaptor.capture());
                var auditEventsCaptured = auditEventCaptor.getAllValues();

                assertEquals(
                        AuditEventTypes.IPV_CONTINUITY_OF_IDENTITY_CHECK_START,
                        auditEventsCaptured.get(0).getEventName());
                assertEquals(
                        new AuditExtensionCoiCheck(FULL_NAME_AND_DOB, null),
                        auditEventsCaptured.get(0).getExtensions());
                assertEquals(
                        AuditEventTypes.IPV_CONTINUITY_OF_IDENTITY_CHECK_END,
                        auditEventsCaptured.get(1).getEventName());
                assertEquals(
                        new AuditExtensionCoiCheck(FULL_NAME_AND_DOB, false),
                        auditEventsCaptured.get(1).getExtensions());
                var restrictedAuditData =
                        getRestrictedAuditDataNodeFromEvent(auditEventsCaptured.get(1));
                assertTrue(restrictedAuditData.has("newName"));
                assertTrue(restrictedAuditData.has("oldName"));
                assertTrue(restrictedAuditData.has("newBirthDate"));
                assertTrue(restrictedAuditData.has("oldBirthDate"));
                assertTrue(restrictedAuditData.has("device_information"));
            }
        }

        private JsonNode getRestrictedAuditDataNodeFromEvent(AuditEvent auditEvent)
                throws Exception {
            var coiCheckEndAuditEvent = getJsonNodeForAuditEvent(auditEvent);
            return coiCheckEndAuditEvent.get("restricted");
        }
    }

    @Nested
    @DisplayName("Errors")
    class Errors {
        @Test
        @MockitoSettings(strictness = LENIENT)
        void shouldReturnErrorIfIpvSessionIdNotFound() throws SqsException {
            var request = ProcessRequest.processRequestBuilder().ipvSessionId(null).build();

            var responseMap = checkCoiHandler.handleRequest(request, mockContext);

            assertEquals(JOURNEY_ERROR_PATH, responseMap.get("journey"));
            assertEquals(MISSING_IPV_SESSION_ID.getMessage(), responseMap.get("message"));
            verify(mockAuditService, times(0)).sendAuditEvent(any());
        }

        @Test
        @MockitoSettings(strictness = LENIENT)
        void shouldReturnErrorIfCheckTypeNotInRequest() {
            var request =
                    ProcessRequest.processRequestBuilder().ipvSessionId(IPV_SESSION_ID).build();

            var responseMap = checkCoiHandler.handleRequest(request, mockContext);

            assertEquals(JOURNEY_ERROR_PATH, responseMap.get("journey"));
            assertEquals(MISSING_CHECK_TYPE.getMessage(), responseMap.get("message"));
        }

        @Test
        void shouldReturnErrorIfFamilyNameCorrelationCheckThrowsHttpResponseException()
                throws Exception {
            when(mockUserIdentityService.areFamilyNameAndDobCorrelatedForCoiCheck(
                            List.of(M1A_ADDRESS_VC, M1A_EXPERIAN_FRAUD_VC)))
                    .thenThrow(
                            new HttpResponseExceptionWithErrorBody(
                                    SC_SERVER_ERROR, FAILED_NAME_CORRELATION));

            var request =
                    ProcessRequest.processRequestBuilder()
                            .ipvSessionId(IPV_SESSION_ID)
                            .lambdaInput(Map.of("checkType", FAMILY_NAME_AND_DOB.name()))
                            .build();

            var responseMap = checkCoiHandler.handleRequest(request, mockContext);

            assertEquals(JOURNEY_ERROR_PATH, responseMap.get("journey"));
            assertEquals(FAILED_NAME_CORRELATION.getMessage(), responseMap.get("message"));
            verify(mockAuditService, times(1)).sendAuditEvent(auditEventCaptor.capture());
            var auditEventsCaptured = auditEventCaptor.getAllValues();

            assertEquals(
                    AuditEventTypes.IPV_CONTINUITY_OF_IDENTITY_CHECK_START,
                    auditEventsCaptured.get(0).getEventName());
            assertEquals(
                    new AuditExtensionCoiCheck(CoiCheckType.FAMILY_NAME_AND_DOB, null),
                    auditEventsCaptured.get(0).getExtensions());
        }

        @Test
        void shouldReturnErrorIfGivenNameCorrelationCheckThrowsHttpResponseException()
                throws Exception {
            when(mockUserIdentityService.areGivenNamesAndDobCorrelated(
                            List.of(M1A_ADDRESS_VC, M1A_EXPERIAN_FRAUD_VC)))
                    .thenThrow(
                            new HttpResponseExceptionWithErrorBody(
                                    SC_SERVER_ERROR, FAILED_NAME_CORRELATION));

            var request =
                    ProcessRequest.processRequestBuilder()
                            .ipvSessionId(IPV_SESSION_ID)
                            .lambdaInput(Map.of("checkType", GIVEN_NAMES_AND_DOB.name()))
                            .build();

            var responseMap = checkCoiHandler.handleRequest(request, mockContext);

            assertEquals(JOURNEY_ERROR_PATH, responseMap.get("journey"));
            assertEquals(FAILED_NAME_CORRELATION.getMessage(), responseMap.get("message"));
            verify(mockAuditService, times(1)).sendAuditEvent(auditEventCaptor.capture());
            var auditEventsCaptured = auditEventCaptor.getAllValues();

            assertEquals(
                    AuditEventTypes.IPV_CONTINUITY_OF_IDENTITY_CHECK_START,
                    auditEventsCaptured.get(0).getEventName());
            assertEquals(
                    new AuditExtensionCoiCheck(CoiCheckType.GIVEN_NAMES_AND_DOB, null),
                    auditEventsCaptured.get(0).getExtensions());
        }

        @Test
        void shouldReturnErrorIfAreVcsCorrelatedCheckThrowsHttpResponseException()
                throws Exception {
            when(mockUserIdentityService.areVcsCorrelated(
                            List.of(M1A_ADDRESS_VC, M1A_EXPERIAN_FRAUD_VC)))
                    .thenThrow(
                            new HttpResponseExceptionWithErrorBody(
                                    SC_SERVER_ERROR, FAILED_NAME_CORRELATION));

            var request =
                    ProcessRequest.processRequestBuilder()
                            .ipvSessionId(IPV_SESSION_ID)
                            .lambdaInput(Map.of("checkType", FULL_NAME_AND_DOB.name()))
                            .build();

            var responseMap = checkCoiHandler.handleRequest(request, mockContext);

            assertEquals(JOURNEY_ERROR_PATH, responseMap.get("journey"));
            assertEquals(FAILED_NAME_CORRELATION.getMessage(), responseMap.get("message"));
            verify(mockAuditService, times(1)).sendAuditEvent(auditEventCaptor.capture());
            var auditEventsCaptured = auditEventCaptor.getAllValues();

            assertEquals(
                    AuditEventTypes.IPV_CONTINUITY_OF_IDENTITY_CHECK_START,
                    auditEventsCaptured.get(0).getEventName());
            assertEquals(
                    new AuditExtensionCoiCheck(CoiCheckType.FULL_NAME_AND_DOB, null),
                    auditEventsCaptured.get(0).getExtensions());
        }

        @Test
        void shouldReturnErrorIfGettingSessionCredentialsThrows() throws Exception {
            when(mockSessionCredentialService.getCredentials(IPV_SESSION_ID, USER_ID))
                    .thenThrow(
                            new VerifiableCredentialException(
                                    SC_SERVER_ERROR, FAILED_TO_GET_CREDENTIAL));

            var request =
                    ProcessRequest.processRequestBuilder()
                            .ipvSessionId(IPV_SESSION_ID)
                            .lambdaInput(Map.of("checkType", FULL_NAME_AND_DOB.name()))
                            .build();

            var responseMap = checkCoiHandler.handleRequest(request, mockContext);

            assertEquals(JOURNEY_ERROR_PATH, responseMap.get("journey"));
            assertEquals(FAILED_TO_GET_CREDENTIAL.getMessage(), responseMap.get("message"));
            verify(mockAuditService, times(1)).sendAuditEvent(auditEventCaptor.capture());
            var auditEventsCaptured = auditEventCaptor.getAllValues();

            assertEquals(
                    AuditEventTypes.IPV_CONTINUITY_OF_IDENTITY_CHECK_START,
                    auditEventsCaptured.get(0).getEventName());
            assertEquals(
                    new AuditExtensionCoiCheck(FULL_NAME_AND_DOB, null),
                    auditEventsCaptured.get(0).getExtensions());
        }

        @Test
        @MockitoSettings(strictness = LENIENT)
        void shouldReturnErrorIfUnknownCheckType() {
            var request =
                    ProcessRequest.processRequestBuilder()
                            .ipvSessionId(IPV_SESSION_ID)
                            .lambdaInput(Map.of("checkType", "sausages"))
                            .build();

            var responseMap = checkCoiHandler.handleRequest(request, mockContext);

            assertEquals(JOURNEY_ERROR_PATH, responseMap.get("journey"));
            assertEquals(UNKNOWN_CHECK_TYPE.getMessage(), responseMap.get("message"));
        }

        @Test
        void shouldReturnIfFindIdentityClaimThrowsHttpResponseException() throws Exception {
            when(mockUserIdentityService.areGivenNamesAndDobCorrelated(
                            List.of(M1A_ADDRESS_VC, M1A_EXPERIAN_FRAUD_VC)))
                    .thenReturn(true);
            when(mockUserIdentityService.findIdentityClaim(any()))
                    .thenThrow(
                            new HttpResponseExceptionWithErrorBody(
                                    500, ErrorResponse.FAILED_TO_GENERATE_IDENTIY_CLAIM));

            var request =
                    ProcessRequest.processRequestBuilder()
                            .ipvSessionId(IPV_SESSION_ID)
                            .lambdaInput(Map.of("checkType", GIVEN_NAMES_AND_DOB.name()))
                            .build();

            var responseMap = checkCoiHandler.handleRequest(request, mockContext);

            assertEquals(JOURNEY_ERROR_PATH, responseMap.get("journey"));
            assertEquals(FAILED_TO_GENERATE_IDENTIY_CLAIM.getMessage(), responseMap.get("message"));
            verify(mockAuditService, times(1)).sendAuditEvent(auditEventCaptor.capture());
        }
    }

    private JsonNode getJsonNodeForAuditEvent(AuditEvent object) throws Exception {
        ObjectMapper mapper = new ObjectMapper();
        String json = mapper.writeValueAsString(object);
        JsonParser parser = mapper.createParser(json);
        return mapper.readTree(parser);
    }
}
