package uk.gov.di.ipv.core.builduseridentity;

import com.amazonaws.services.lambda.runtime.Context;
import com.amazonaws.services.lambda.runtime.events.APIGatewayProxyRequestEvent;
import com.amazonaws.services.lambda.runtime.events.APIGatewayProxyResponseEvent;
import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.nimbusds.oauth2.sdk.OAuth2Error;
import com.nimbusds.oauth2.sdk.http.HTTPResponse;
import com.nimbusds.oauth2.sdk.token.AccessToken;
import com.nimbusds.oauth2.sdk.token.BearerAccessToken;
import com.nimbusds.oauth2.sdk.token.BearerTokenError;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.ArgumentCaptor;
import org.mockito.InOrder;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import uk.gov.di.ipv.core.library.auditing.AuditEvent;
import uk.gov.di.ipv.core.library.auditing.AuditEventTypes;
import uk.gov.di.ipv.core.library.auditing.extension.AuditExtensionsUserIdentity;
import uk.gov.di.ipv.core.library.config.domain.Config;
import uk.gov.di.ipv.core.library.domain.*;
import uk.gov.di.ipv.core.library.dto.AccessTokenMetadata;
import uk.gov.di.ipv.core.library.enums.Vot;
import uk.gov.di.ipv.core.library.exceptions.CiExtractionException;
import uk.gov.di.ipv.core.library.exceptions.HttpResponseExceptionWithErrorBody;
import uk.gov.di.ipv.core.library.exceptions.IpvSessionNotFoundException;
import uk.gov.di.ipv.core.library.exceptions.UnrecognisedCiException;
import uk.gov.di.ipv.core.library.exceptions.VerifiableCredentialException;
import uk.gov.di.ipv.core.library.helpers.SecureTokenHelper;
import uk.gov.di.ipv.core.library.helpers.vocab.BirthDateGenerator;
import uk.gov.di.ipv.core.library.persistence.item.ClientOAuthSessionItem;
import uk.gov.di.ipv.core.library.persistence.item.IpvSessionItem;
import uk.gov.di.ipv.core.library.service.AuditService;
import uk.gov.di.ipv.core.library.service.CimitUtilityService;
import uk.gov.di.ipv.core.library.service.ClientOAuthSessionDetailsService;
import uk.gov.di.ipv.core.library.service.ConfigService;
import uk.gov.di.ipv.core.library.service.IpvSessionService;
import uk.gov.di.ipv.core.library.testhelpers.unit.LogCollector;
import uk.gov.di.ipv.core.library.useridentity.service.UserIdentityService;
import uk.gov.di.ipv.core.library.verifiablecredential.service.SessionCredentialsService;
import uk.gov.di.model.BirthDate;
import uk.gov.di.model.ContraIndicator;
import uk.gov.di.model.DrivingPermitDetails;
import uk.gov.di.model.Mitigation;
import uk.gov.di.model.Name;
import uk.gov.di.model.NamePart;
import uk.gov.di.model.PassportDetails;
import uk.gov.di.model.PostalAddress;
import uk.gov.di.model.SocialSecurityRecordDetails;

import java.net.URI;
import java.net.URISyntaxException;
import java.time.Instant;
import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import static java.lang.String.valueOf;
import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.core.StringContains.containsString;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.*;
import static uk.gov.di.ipv.core.library.config.CoreFeatureFlag.MFA_RESET;
import static uk.gov.di.ipv.core.library.domain.ErrorResponse.FAILED_TO_GET_CREDENTIAL;
import static uk.gov.di.ipv.core.library.domain.IpvJourneyTypes.INITIAL_JOURNEY_SELECTION;
import static uk.gov.di.ipv.core.library.fixtures.TestFixtures.ADDRESS_JSON_1;
import static uk.gov.di.ipv.core.library.fixtures.TestFixtures.DRIVING_PERMIT_JSON_1;
import static uk.gov.di.ipv.core.library.fixtures.TestFixtures.NINO_JSON_1;
import static uk.gov.di.ipv.core.library.fixtures.TestFixtures.PASSPORT_JSON_1;
import static uk.gov.di.ipv.core.library.fixtures.TestFixtures.SIGNED_CONTRA_INDICATOR_VC_1;
import static uk.gov.di.ipv.core.library.fixtures.VcFixtures.vcAddressOne;
import static uk.gov.di.ipv.core.library.fixtures.VcFixtures.vcTicf;
import static uk.gov.di.ipv.core.library.helpers.vocab.NameGenerator.NamePartGenerator.createNamePart;
import static uk.gov.di.ipv.core.library.helpers.vocab.NameGenerator.createName;

@ExtendWith(MockitoExtension.class)
class BuildUserIdentityHandlerTest {

    private static final ObjectMapper OBJECT_MAPPER = new ObjectMapper();
    private static final String TEST_IPV_SESSION_ID = SecureTokenHelper.getInstance().generate();
    private static final String TEST_USER_ID = "test-user-id";
    private static final String TEST_ACCESS_TOKEN = "test-access-token";
    private static final String VTM = "http://www.example.com/vtm";
    private static final String TEST_IP_ADDRESS = "192.168.1.100";
    private static final String OPENID_SCOPE = "openid email phone";
    private static final String USER_IDENTITY_REQUEST = "/user-identity";
    private static final String TEST_CLIENT_OAUTH_SESSION_ID =
            SecureTokenHelper.getInstance().generate();
    private static final List<ContraIndicator> CONTRA_INDICATORS =
            List.of(
                    createCi(
                            "X01",
                            List.of(
                                    "https://review-d.account.gov.uk",
                                    "https://review-f.account.gov.uk")),
                    createCi(
                            "X02",
                            List.of(
                                    "https://review-q.account.gov.uk",
                                    "https://review-f.account.gov.uk")),
                    createCi(
                            "Z03",
                            List.of(
                                    "https://review-z.account.gov.uk",
                                    "https://review-f.account.gov.uk")));
    private static final APIGatewayProxyRequestEvent testEvent = getEventWithAuthAndIpHeaders();

    @Mock private Context mockContext;
    @Mock private UserIdentityService mockUserIdentityService;
    @Mock private IpvSessionService mockIpvSessionService;
    @Mock private ConfigService mockConfigService;
    @Mock private Config mockConfig;
    @Mock private AuditService mockAuditService;
    @Mock private ClientOAuthSessionDetailsService mockClientOAuthSessionDetailsService;
    @Mock private CimitUtilityService mockCimitUtilityService;
    @Mock private SessionCredentialsService mockSessionCredentialsService;
    @InjectMocks private BuildUserIdentityHandler buildUserIdentityHandler;

    private UserIdentity userIdentity;
    private IpvSessionItem ipvSessionItem;
    private ClientOAuthSessionItem clientOAuthSessionItem;
    private Map<String, String> responseBody;

    @BeforeEach
    void setUp() throws Exception {
        responseBody = new HashMap<>();

        List<Name> names =
                Collections.singletonList(
                        createName(
                                Collections.singletonList(
                                        createNamePart(
                                                "Daniel", NamePart.NamePartType.GIVEN_NAME))));

        List<BirthDate> birthDates =
                Collections.singletonList(BirthDateGenerator.createBirthDate("1990-02-10"));

        userIdentity =
                new UserIdentity(
                        List.of("12345", "Test credential", "bar"),
                        new IdentityClaim(names, birthDates),
                        List.of(OBJECT_MAPPER.readValue(ADDRESS_JSON_1, PostalAddress.class)),
                        List.of(OBJECT_MAPPER.readValue(PASSPORT_JSON_1, PassportDetails.class)),
                        List.of(
                                OBJECT_MAPPER.readValue(
                                        DRIVING_PERMIT_JSON_1, DrivingPermitDetails.class)),
                        List.of(
                                OBJECT_MAPPER.readValue(
                                        NINO_JSON_1, SocialSecurityRecordDetails.class)),
                        "test-sub",
                        Vot.P2,
                        VTM,
                        List.of(new ReturnCode("1"), new ReturnCode("2"), new ReturnCode("3")));

        ipvSessionItem = new IpvSessionItem();
        ipvSessionItem.setIpvSessionId(TEST_IPV_SESSION_ID);
        ipvSessionItem.pushState(new JourneyState(INITIAL_JOURNEY_SELECTION, "test-state"));
        ipvSessionItem.setClientOAuthSessionId(TEST_CLIENT_OAUTH_SESSION_ID);
        ipvSessionItem.setAccessToken(TEST_ACCESS_TOKEN);
        ipvSessionItem.setAccessTokenMetadata(new AccessTokenMetadata());
        ipvSessionItem.setVot(Vot.P2);
        ipvSessionItem.setFeatureSet("someCoolNewThing");
        ipvSessionItem.setSecurityCheckCredential(SIGNED_CONTRA_INDICATOR_VC_1);

        clientOAuthSessionItem = getClientAuthSessionItemWithScope(OPENID_SCOPE);

        when(mockConfigService.getComponentId()).thenReturn("https://core-component.example");
    }

    @AfterEach
    void checkAuditEventWait() {
        InOrder auditInOrder = inOrder(mockAuditService);
        auditInOrder.verify(mockAuditService).awaitAuditEvents();
        auditInOrder.verifyNoMoreInteractions();
    }

    @Test
    void shouldReturnCredentialsWithCimitVCOnSuccessfulUserInfoRequest() throws Exception {
        // Arrange
        var addressVc = vcAddressOne();
        when(mockIpvSessionService.getIpvSessionByAccessToken(TEST_ACCESS_TOKEN))
                .thenReturn(ipvSessionItem);
        when(mockUserIdentityService.generateUserIdentity(any(), any(), any(), any(), any()))
                .thenReturn(userIdentity);
        when(mockClientOAuthSessionDetailsService.getClientOAuthSession(any()))
                .thenReturn(clientOAuthSessionItem);

        var mitigatedCi = new ContraIndicator();
        mitigatedCi.setCode("test_code");
        mitigatedCi.setMitigation(List.of(new Mitigation()));
        var testCis = List.of(mitigatedCi);

        when(mockCimitUtilityService.getContraIndicatorsFromVc(any(), any())).thenReturn(testCis);
        when(mockConfigService.enabled(MFA_RESET)).thenReturn(false);
        when(mockSessionCredentialsService.getCredentials(TEST_IPV_SESSION_ID, TEST_USER_ID))
                .thenReturn(List.of(addressVc));

        // Act
        APIGatewayProxyResponseEvent response =
                buildUserIdentityHandler.handleRequest(testEvent, mockContext);

        // Assert
        assertEquals(200, response.getStatusCode());

        UserIdentity userIdentityResponse =
                OBJECT_MAPPER.readValue(response.getBody(), new TypeReference<>() {});

        assertEquals(4, userIdentityResponse.getVcs().size());
        assertEquals(userIdentity.getVcs(), userIdentityResponse.getVcs());
        assertEquals(userIdentity.getIdentityClaim(), userIdentityResponse.getIdentityClaim());
        assertEquals(userIdentity.getAddressClaim(), userIdentityResponse.getAddressClaim());
        assertEquals(
                userIdentity.getDrivingPermitClaim(), userIdentityResponse.getDrivingPermitClaim());
        assertEquals(userIdentity.getNinoClaim(), userIdentityResponse.getNinoClaim());

        verify(mockIpvSessionService).revokeAccessToken(ipvSessionItem);

        ArgumentCaptor<AuditEvent> auditEventCaptor = ArgumentCaptor.forClass(AuditEvent.class);
        verify(mockAuditService).sendAuditEvent(auditEventCaptor.capture());

        AuditEvent capturedAuditEvent = auditEventCaptor.getValue();
        assertEquals(AuditEventTypes.IPV_IDENTITY_ISSUED, capturedAuditEvent.getEventName());
        AuditExtensionsUserIdentity extensions =
                (AuditExtensionsUserIdentity) capturedAuditEvent.getExtensions();
        assertEquals(Vot.P2, extensions.getLevelOfConfidence());
        assertFalse(extensions.isCiFail());
        assertTrue(extensions.isHasMitigations());
        assertEquals(3, userIdentityResponse.getReturnCode().size());
        verify(mockClientOAuthSessionDetailsService, times(1)).getClientOAuthSession(any());
        verify(mockCimitUtilityService, times(1)).getContraIndicatorsFromVc(any(), any());

        verify(mockConfigService).setFeatureSet(List.of("someCoolNewThing"));

        verify(mockUserIdentityService)
                .generateUserIdentity(List.of(addressVc), TEST_USER_ID, Vot.P2, Vot.P2, testCis);

        verify(mockSessionCredentialsService, times(1))
                .deleteSessionCredentials(TEST_IPV_SESSION_ID);
    }

    @Test
    void shouldReturnCredentialsWithP1OnSuccessfulUserInfoRequestForP1() throws Exception {
        // Arrange
        var addressVc = vcAddressOne();
        ipvSessionItem.setVot(Vot.P1);
        when(mockIpvSessionService.getIpvSessionByAccessToken(TEST_ACCESS_TOKEN))
                .thenReturn(ipvSessionItem);
        when(mockUserIdentityService.generateUserIdentity(any(), any(), any(), any(), any()))
                .thenReturn(userIdentity);
        when(mockClientOAuthSessionDetailsService.getClientOAuthSession(any()))
                .thenReturn(clientOAuthSessionItem);

        var mitigatedCi = new ContraIndicator();
        mitigatedCi.setCode("test_code");
        mitigatedCi.setMitigation(List.of(new Mitigation()));
        var testCis = List.of(mitigatedCi);

        when(mockCimitUtilityService.getContraIndicatorsFromVc(any(), any())).thenReturn(testCis);
        when(mockConfigService.enabled(MFA_RESET)).thenReturn(false);
        when(mockSessionCredentialsService.getCredentials(TEST_IPV_SESSION_ID, TEST_USER_ID))
                .thenReturn(List.of(addressVc));

        // Act
        APIGatewayProxyResponseEvent response =
                buildUserIdentityHandler.handleRequest(testEvent, mockContext);

        // Assert
        assertEquals(200, response.getStatusCode());

        UserIdentity userIdentityResponse =
                OBJECT_MAPPER.readValue(response.getBody(), new TypeReference<>() {});

        assertEquals(4, userIdentityResponse.getVcs().size());
        assertEquals(userIdentity.getVcs(), userIdentityResponse.getVcs());
        assertEquals(userIdentity.getIdentityClaim(), userIdentityResponse.getIdentityClaim());
        assertEquals(userIdentity.getAddressClaim(), userIdentityResponse.getAddressClaim());
        assertEquals(
                userIdentity.getDrivingPermitClaim(), userIdentityResponse.getDrivingPermitClaim());
        assertEquals(userIdentity.getNinoClaim(), userIdentityResponse.getNinoClaim());

        verify(mockIpvSessionService).revokeAccessToken(ipvSessionItem);

        ArgumentCaptor<AuditEvent> auditEventCaptor = ArgumentCaptor.forClass(AuditEvent.class);
        verify(mockAuditService).sendAuditEvent(auditEventCaptor.capture());

        AuditEvent capturedAuditEvent = auditEventCaptor.getValue();
        assertEquals(AuditEventTypes.IPV_IDENTITY_ISSUED, capturedAuditEvent.getEventName());
        AuditExtensionsUserIdentity extensions =
                (AuditExtensionsUserIdentity) capturedAuditEvent.getExtensions();
        assertEquals(Vot.P1, extensions.getLevelOfConfidence());
        assertFalse(extensions.isCiFail());
        assertTrue(extensions.isHasMitigations());
        assertEquals(3, userIdentityResponse.getReturnCode().size());
        verify(mockClientOAuthSessionDetailsService, times(1)).getClientOAuthSession(any());
        verify(mockCimitUtilityService, times(1)).getContraIndicatorsFromVc(any(), any());

        verify(mockConfigService).setFeatureSet(List.of("someCoolNewThing"));

        verify(mockUserIdentityService)
                .generateUserIdentity(List.of(addressVc), TEST_USER_ID, Vot.P1, Vot.P1, testCis);

        verify(mockSessionCredentialsService, times(1))
                .deleteSessionCredentials(TEST_IPV_SESSION_ID);
    }

    @Test
    void
            shouldReturnCredentialsWithCimitVCOnSuccessfulUserInfoRequestWhenDeleteSessionCredentialsError()
                    throws Exception {
        // Arrange
        var addressVc = vcAddressOne();
        when(mockIpvSessionService.getIpvSessionByAccessToken(TEST_ACCESS_TOKEN))
                .thenReturn(ipvSessionItem);
        when(mockUserIdentityService.generateUserIdentity(any(), any(), any(), any(), any()))
                .thenReturn(userIdentity);
        when(mockClientOAuthSessionDetailsService.getClientOAuthSession(any()))
                .thenReturn(clientOAuthSessionItem);

        var mitigatedCi = new ContraIndicator();
        mitigatedCi.setCode("test_code");
        mitigatedCi.setMitigation(List.of(new Mitigation()));
        var testCis = List.of(mitigatedCi);

        when(mockCimitUtilityService.getContraIndicatorsFromVc(any(), any())).thenReturn(testCis);
        when(mockConfigService.enabled(MFA_RESET)).thenReturn(false);
        when(mockSessionCredentialsService.getCredentials(TEST_IPV_SESSION_ID, TEST_USER_ID))
                .thenReturn(List.of(addressVc));
        doThrow(
                        new VerifiableCredentialException(
                                HTTPResponse.SC_SERVER_ERROR,
                                ErrorResponse.FAILED_TO_DELETE_CREDENTIAL))
                .when(mockSessionCredentialsService)
                .deleteSessionCredentials(any());
        // Act
        APIGatewayProxyResponseEvent response =
                buildUserIdentityHandler.handleRequest(testEvent, mockContext);

        // Assert
        assertEquals(200, response.getStatusCode());

        UserIdentity userIdentityResponse =
                OBJECT_MAPPER.readValue(response.getBody(), new TypeReference<>() {});

        assertEquals(4, userIdentityResponse.getVcs().size());
        assertEquals(userIdentity.getVcs(), userIdentityResponse.getVcs());
        assertEquals(userIdentity.getIdentityClaim(), userIdentityResponse.getIdentityClaim());
        assertEquals(userIdentity.getAddressClaim(), userIdentityResponse.getAddressClaim());
        assertEquals(
                userIdentity.getDrivingPermitClaim(), userIdentityResponse.getDrivingPermitClaim());
        assertEquals(userIdentity.getNinoClaim(), userIdentityResponse.getNinoClaim());

        verify(mockIpvSessionService).revokeAccessToken(ipvSessionItem);

        ArgumentCaptor<AuditEvent> auditEventCaptor = ArgumentCaptor.forClass(AuditEvent.class);
        verify(mockAuditService).sendAuditEvent(auditEventCaptor.capture());

        AuditEvent capturedAuditEvent = auditEventCaptor.getValue();
        assertEquals(AuditEventTypes.IPV_IDENTITY_ISSUED, capturedAuditEvent.getEventName());
        AuditExtensionsUserIdentity extensions =
                (AuditExtensionsUserIdentity) capturedAuditEvent.getExtensions();
        assertEquals(Vot.P2, extensions.getLevelOfConfidence());
        assertFalse(extensions.isCiFail());
        assertTrue(extensions.isHasMitigations());
        assertEquals(3, userIdentityResponse.getReturnCode().size());
        verify(mockClientOAuthSessionDetailsService, times(1)).getClientOAuthSession(any());
        verify(mockCimitUtilityService, times(1)).getContraIndicatorsFromVc(any(), any());

        verify(mockConfigService).setFeatureSet(List.of("someCoolNewThing"));

        verify(mockUserIdentityService)
                .generateUserIdentity(List.of(addressVc), TEST_USER_ID, Vot.P2, Vot.P2, testCis);

        verify(mockSessionCredentialsService, times(1))
                .deleteSessionCredentials(TEST_IPV_SESSION_ID);
    }

    @Test
    void
            shouldReturnCredentialsWithCimitVCOnSuccessfulUserInfoRequestAndHasMitigationsFalseAndOnlyNotFoundReturnCodeInCiConfigForAuditEventReturnCodes()
                    throws Exception {
        // Arrange
        when(mockConfigService.getContraIndicatorConfigMap())
                .thenReturn(
                        Map.of(
                                "X01", new ContraIndicatorConfig("X01", 4, -3, "4"),
                                "X02", new ContraIndicatorConfig("X02", 4, -3, "2"),
                                "Z03", new ContraIndicatorConfig("Z03", 4, -3, "3")));
        ipvSessionItem.setVot(Vot.P0);
        when(mockIpvSessionService.getIpvSessionByAccessToken(TEST_ACCESS_TOKEN))
                .thenReturn(ipvSessionItem);
        when(mockUserIdentityService.generateUserIdentity(any(), any(), any(), any(), any()))
                .thenReturn(userIdentity);
        when(mockClientOAuthSessionDetailsService.getClientOAuthSession(any()))
                .thenReturn(clientOAuthSessionItem);
        when(mockCimitUtilityService.getContraIndicatorsFromVc(any(), any()))
                .thenReturn(CONTRA_INDICATORS);
        // Act
        APIGatewayProxyResponseEvent response =
                buildUserIdentityHandler.handleRequest(testEvent, mockContext);

        // Assert
        assertEquals(200, response.getStatusCode());

        UserIdentity userIdentityResponse =
                OBJECT_MAPPER.readValue(response.getBody(), new TypeReference<>() {});

        assertEquals(4, userIdentityResponse.getVcs().size());
        assertEquals(userIdentity.getVcs(), userIdentityResponse.getVcs());
        assertEquals(userIdentity.getIdentityClaim(), userIdentityResponse.getIdentityClaim());
        assertEquals(userIdentity.getAddressClaim(), userIdentityResponse.getAddressClaim());
        assertEquals(
                userIdentity.getDrivingPermitClaim(), userIdentityResponse.getDrivingPermitClaim());
        assertEquals(userIdentity.getNinoClaim(), userIdentityResponse.getNinoClaim());
        assertEquals(
                userIdentity.getReturnCode().size(), userIdentityResponse.getReturnCode().size());

        verify(mockIpvSessionService).revokeAccessToken(ipvSessionItem);

        ArgumentCaptor<AuditEvent> auditEventCaptor = ArgumentCaptor.forClass(AuditEvent.class);
        verify(mockAuditService).sendAuditEvent(auditEventCaptor.capture());

        AuditEvent capturedAuditEvent = auditEventCaptor.getValue();
        assertEquals(AuditEventTypes.IPV_IDENTITY_ISSUED, capturedAuditEvent.getEventName());
        var expectedExtension =
                new AuditExtensionsUserIdentity(
                        Vot.P0,
                        false,
                        false,
                        List.of(
                                new AuditEventReturnCode("1", List.of()),
                                new AuditEventReturnCode(
                                        "2",
                                        List.of(
                                                "https://review-q.account.gov.uk",
                                                "https://review-f.account.gov.uk")),
                                new AuditEventReturnCode(
                                        "3",
                                        List.of(
                                                "https://review-z.account.gov.uk",
                                                "https://review-f.account.gov.uk"))));
        assertEquals(expectedExtension, capturedAuditEvent.getExtensions());

        verify(mockClientOAuthSessionDetailsService, times(1)).getClientOAuthSession(any());
        verify(mockCimitUtilityService, times(1)).getContraIndicatorsFromVc(any(), any());

        verify(mockConfigService).setFeatureSet(List.of("someCoolNewThing"));
        verify(mockSessionCredentialsService, times(1))
                .deleteSessionCredentials(TEST_IPV_SESSION_ID);
    }

    @Test
    void shouldReturnRiskAssessmentCredentialsWhenTicfIsEnabled() throws Exception {
        // Arrange
        when(mockConfigService.getContraIndicatorConfigMap())
                .thenReturn(
                        Map.of(
                                "X01", new ContraIndicatorConfig("X01", 4, -3, "4"),
                                "X02", new ContraIndicatorConfig("X02", 4, -3, "2"),
                                "Z03", new ContraIndicatorConfig("Z03", 4, -3, "3")));
        ipvSessionItem.setVot(Vot.P0);
        ipvSessionItem.setRiskAssessmentCredential(vcTicf().getVcString());
        when(mockIpvSessionService.getIpvSessionByAccessToken(TEST_ACCESS_TOKEN))
                .thenReturn(ipvSessionItem);
        when(mockUserIdentityService.generateUserIdentity(any(), any(), any(), any(), any()))
                .thenReturn(userIdentity);
        when(mockClientOAuthSessionDetailsService.getClientOAuthSession(any()))
                .thenReturn(clientOAuthSessionItem);
        when(mockCimitUtilityService.getContraIndicatorsFromVc(any(), any()))
                .thenReturn(CONTRA_INDICATORS);
        when(mockConfigService.isCredentialIssuerEnabled(Cri.TICF.getId())).thenReturn(true);
        when(mockConfigService.enabled(MFA_RESET)).thenReturn(false);
        // Act
        APIGatewayProxyResponseEvent response =
                buildUserIdentityHandler.handleRequest(testEvent, mockContext);

        // Assert
        assertEquals(200, response.getStatusCode());

        UserIdentity userIdentityResponse =
                OBJECT_MAPPER.readValue(response.getBody(), new TypeReference<>() {});

        assertEquals(5, userIdentityResponse.getVcs().size());
        assertEquals(userIdentity.getVcs(), userIdentityResponse.getVcs());
        assertEquals(userIdentity.getIdentityClaim(), userIdentityResponse.getIdentityClaim());
        assertEquals(userIdentity.getAddressClaim(), userIdentityResponse.getAddressClaim());
        assertEquals(
                userIdentity.getDrivingPermitClaim(), userIdentityResponse.getDrivingPermitClaim());
        assertEquals(userIdentity.getNinoClaim(), userIdentityResponse.getNinoClaim());
        assertEquals(
                userIdentity.getReturnCode().size(), userIdentityResponse.getReturnCode().size());
        verify(mockSessionCredentialsService, times(1))
                .deleteSessionCredentials(TEST_IPV_SESSION_ID);
    }

    @Test
    void
            shouldReturnCredentialsWithCimitVCOnSuccessfulUserInfoRequestAndHasMitigationsFalseCiConfigForAuditEventReturnCodesAndCheckedDuplicateIssuers()
                    throws Exception {
        var contraIndicators =
                List.of(
                        createCi(
                                "X01",
                                List.of(
                                        "https://review-d.account.gov.uk",
                                        "https://review-f.account.gov.uk")),
                        createCi(
                                "X02",
                                List.of(
                                        "https://review-d.account.gov.uk",
                                        "https://review-f.account.gov.uk")),
                        createCi(
                                "Z03",
                                List.of(
                                        "https://review-w.account.gov.uk",
                                        "https://review-x.account.gov.uk")));

        // Arrange
        when(mockConfigService.getContraIndicatorConfigMap())
                .thenReturn(
                        Map.of(
                                "X01", new ContraIndicatorConfig("X01", 4, -3, "1"),
                                "X02", new ContraIndicatorConfig("X02", 4, -3, "1"),
                                "Z03", new ContraIndicatorConfig("Z03", 4, -3, "3")));
        when(mockCimitUtilityService.isBreachingCiThreshold(any(), any())).thenReturn(false);
        ipvSessionItem.setVot(Vot.P0);
        when(mockIpvSessionService.getIpvSessionByAccessToken(TEST_ACCESS_TOKEN))
                .thenReturn(ipvSessionItem);
        when(mockUserIdentityService.generateUserIdentity(any(), any(), any(), any(), any()))
                .thenReturn(userIdentity);
        when(mockClientOAuthSessionDetailsService.getClientOAuthSession(any()))
                .thenReturn(clientOAuthSessionItem);
        when(mockCimitUtilityService.getContraIndicatorsFromVc(any(), any()))
                .thenReturn(contraIndicators);
        when(mockConfigService.enabled(MFA_RESET)).thenReturn(false);
        // Act
        APIGatewayProxyResponseEvent response =
                buildUserIdentityHandler.handleRequest(testEvent, mockContext);

        // Assert
        assertEquals(200, response.getStatusCode());

        UserIdentity userIdentityResponse =
                OBJECT_MAPPER.readValue(response.getBody(), new TypeReference<>() {});

        assertEquals(4, userIdentityResponse.getVcs().size());
        assertEquals(userIdentity.getVcs(), userIdentityResponse.getVcs());
        assertEquals(userIdentity.getIdentityClaim(), userIdentityResponse.getIdentityClaim());
        assertEquals(userIdentity.getAddressClaim(), userIdentityResponse.getAddressClaim());
        assertEquals(
                userIdentity.getDrivingPermitClaim(), userIdentityResponse.getDrivingPermitClaim());
        assertEquals(userIdentity.getNinoClaim(), userIdentityResponse.getNinoClaim());
        assertEquals(
                userIdentity.getReturnCode().size(), userIdentityResponse.getReturnCode().size());

        verify(mockIpvSessionService).revokeAccessToken(ipvSessionItem);

        ArgumentCaptor<AuditEvent> auditEventCaptor = ArgumentCaptor.forClass(AuditEvent.class);
        verify(mockAuditService).sendAuditEvent(auditEventCaptor.capture());

        AuditEvent capturedAuditEvent = auditEventCaptor.getValue();
        assertEquals(AuditEventTypes.IPV_IDENTITY_ISSUED, capturedAuditEvent.getEventName());
        var expectedExtension =
                new AuditExtensionsUserIdentity(
                        Vot.P0,
                        false,
                        false,
                        List.of(
                                new AuditEventReturnCode(
                                        "1",
                                        List.of(
                                                "https://review-d.account.gov.uk",
                                                "https://review-f.account.gov.uk")),
                                new AuditEventReturnCode("2", List.of()),
                                new AuditEventReturnCode(
                                        "3",
                                        List.of(
                                                "https://review-w.account.gov.uk",
                                                "https://review-x.account.gov.uk"))));
        assertEquals(expectedExtension, capturedAuditEvent.getExtensions());

        verify(mockClientOAuthSessionDetailsService, times(1)).getClientOAuthSession(any());
        verify(mockCimitUtilityService, times(1)).getContraIndicatorsFromVc(any(), any());

        verify(mockConfigService).setFeatureSet(List.of("someCoolNewThing"));
        verify(mockSessionCredentialsService, times(1))
                .deleteSessionCredentials(TEST_IPV_SESSION_ID);
    }

    @Test
    void shouldReturnErrorResponseWhenUserIdentityGenerationFails() throws Exception {
        when(mockIpvSessionService.getIpvSessionByAccessToken(TEST_ACCESS_TOKEN))
                .thenReturn(ipvSessionItem);
        when(mockUserIdentityService.generateUserIdentity(any(), any(), any(), any(), any()))
                .thenThrow(
                        new HttpResponseExceptionWithErrorBody(
                                500, ErrorResponse.FAILED_TO_GENERATE_IDENTITY_CLAIM));
        when(mockClientOAuthSessionDetailsService.getClientOAuthSession(any()))
                .thenReturn(clientOAuthSessionItem);

        APIGatewayProxyResponseEvent response =
                buildUserIdentityHandler.handleRequest(testEvent, mockContext);

        responseBody = OBJECT_MAPPER.readValue(response.getBody(), new TypeReference<>() {});

        assertEquals(500, response.getStatusCode());
        assertEquals(
                valueOf(ErrorResponse.FAILED_TO_GENERATE_IDENTITY_CLAIM.getCode()),
                responseBody.get("error"));
        assertEquals(
                ErrorResponse.FAILED_TO_GENERATE_IDENTITY_CLAIM.getMessage(),
                responseBody.get("error_description"));
        verify(mockClientOAuthSessionDetailsService, times(1)).getClientOAuthSession(any());
        verify(mockSessionCredentialsService, never()).deleteSessionCredentials(any());
    }

    @Test
    void shouldReturnErrorResponseOnCiExtractionException() throws Exception {
        when(mockIpvSessionService.getIpvSessionByAccessToken(TEST_ACCESS_TOKEN))
                .thenReturn(ipvSessionItem);
        when(mockClientOAuthSessionDetailsService.getClientOAuthSession(any()))
                .thenReturn(clientOAuthSessionItem);
        when(mockCimitUtilityService.getContraIndicatorsFromVc(any(), any()))
                .thenThrow(new CiExtractionException("Failed to extract CIs"));

        APIGatewayProxyResponseEvent response =
                buildUserIdentityHandler.handleRequest(testEvent, mockContext);
        responseBody = OBJECT_MAPPER.readValue(response.getBody(), new TypeReference<>() {});

        assertEquals(500, response.getStatusCode());
        assertEquals("server_error", responseBody.get("error"));
        assertEquals(
                "Unexpected server error - Failed to extract contra indicators. Failed to extract CIs",
                responseBody.get("error_description"));
        verify(mockClientOAuthSessionDetailsService, times(1)).getClientOAuthSession(any());
        verify(mockCimitUtilityService, times(1)).getContraIndicatorsFromVc(any(), any());
        verify(mockSessionCredentialsService, never()).deleteSessionCredentials(any());
    }

    @Test
    void shouldReturnErrorResponseWhenMissingSecurityCheckCredentials() throws Exception {
        ipvSessionItem.setSecurityCheckCredential(null);
        when(mockIpvSessionService.getIpvSessionByAccessToken(TEST_ACCESS_TOKEN))
                .thenReturn(ipvSessionItem);
        when(mockClientOAuthSessionDetailsService.getClientOAuthSession(any()))
                .thenReturn(clientOAuthSessionItem);

        APIGatewayProxyResponseEvent response =
                buildUserIdentityHandler.handleRequest(testEvent, mockContext);
        responseBody = OBJECT_MAPPER.readValue(response.getBody(), new TypeReference<>() {});

        assertEquals(500, response.getStatusCode());
        assertEquals("server_error", responseBody.get("error"));
        assertEquals(
                "Unexpected server error - Missing security check credential",
                responseBody.get("error_description"));
        verify(mockClientOAuthSessionDetailsService, times(1)).getClientOAuthSession(any());
        verify(mockSessionCredentialsService, never()).deleteSessionCredentials(any());
    }

    @Test
    void shouldReturnErrorResponseWhenTokenIsNull() throws Exception {
        APIGatewayProxyRequestEvent event = new APIGatewayProxyRequestEvent();
        Map<String, String> headers = new HashMap<>(Collections.emptyMap());
        headers.put("Authorization", null);
        headers.put("ip-address", TEST_IP_ADDRESS);
        event.setHeaders(headers);
        event.setPath(USER_IDENTITY_REQUEST);

        APIGatewayProxyResponseEvent response =
                buildUserIdentityHandler.handleRequest(event, mockContext);
        responseBody = OBJECT_MAPPER.readValue(response.getBody(), new TypeReference<>() {});

        assertEquals(BearerTokenError.MISSING_TOKEN.getHTTPStatusCode(), response.getStatusCode());
        assertEquals(BearerTokenError.MISSING_TOKEN.getCode(), responseBody.get("error"));
        assertEquals(
                BearerTokenError.MISSING_TOKEN.getDescription(),
                responseBody.get("error_description"));
        verify(mockClientOAuthSessionDetailsService, times(0)).getClientOAuthSession(any());
        verify(mockSessionCredentialsService, never()).deleteSessionCredentials(any());
    }

    @Test
    void shouldReturnErrorResponseWhenScopeIsInvalid() throws Exception {
        // Arrange
        ClientOAuthSessionItem clientOAuthSessionItemWithScope =
                getClientAuthSessionItemWithScope("a-different-scope");

        when(mockIpvSessionService.getIpvSessionByAccessToken(TEST_ACCESS_TOKEN))
                .thenReturn(ipvSessionItem);
        when(mockClientOAuthSessionDetailsService.getClientOAuthSession(any()))
                .thenReturn(clientOAuthSessionItemWithScope);
        when(mockConfigService.enabled(MFA_RESET)).thenReturn(true);

        // Act
        APIGatewayProxyResponseEvent response =
                buildUserIdentityHandler.handleRequest(testEvent, mockContext);

        // Assert
        responseBody = OBJECT_MAPPER.readValue(response.getBody(), new TypeReference<>() {});
        assertEquals(OAuth2Error.ACCESS_DENIED.getCode(), responseBody.get("error"));
        assertEquals(
                OAuth2Error.ACCESS_DENIED
                        .appendDescription(
                                " - Access was attempted from an invalid endpoint or journey.")
                        .getDescription(),
                responseBody.get("error_description"));

        verify(mockUserIdentityService, never())
                .generateUserIdentity(any(), any(), any(), any(), any());
        verify(mockSessionCredentialsService, never()).deleteSessionCredentials(any());
    }

    @Test
    void shouldNotReturnErrorResponseWhenScopeIsInvalidAndFeatureDisabled() throws Exception {

        // Arrange
        ClientOAuthSessionItem clientOAuthSessionItemWithScope =
                getClientAuthSessionItemWithScope("a-different-scope");
        // Arrange
        when(mockIpvSessionService.getIpvSessionByAccessToken(TEST_ACCESS_TOKEN))
                .thenReturn(ipvSessionItem);
        when(mockUserIdentityService.generateUserIdentity(any(), any(), any(), any(), any()))
                .thenReturn(userIdentity);
        when(mockClientOAuthSessionDetailsService.getClientOAuthSession(any()))
                .thenReturn(clientOAuthSessionItemWithScope);

        var mitigatedCi = new ContraIndicator();
        mitigatedCi.setCode("test_code");
        mitigatedCi.setMitigation(List.of(new Mitigation()));
        var testCis = List.of(mitigatedCi);

        when(mockCimitUtilityService.getContraIndicatorsFromVc(any(), any())).thenReturn(testCis);
        when(mockConfigService.enabled(MFA_RESET)).thenReturn(false);

        when(mockSessionCredentialsService.getCredentials(TEST_IPV_SESSION_ID, TEST_USER_ID))
                .thenReturn(List.of(vcAddressOne()));

        // Act
        APIGatewayProxyResponseEvent response =
                buildUserIdentityHandler.handleRequest(testEvent, mockContext);

        // Assert
        assertEquals(200, response.getStatusCode());
    }

    @Test
    void shouldReturnErrorResponseWhenTokenIsMissingBearerPrefix() throws Exception {
        APIGatewayProxyRequestEvent event = new APIGatewayProxyRequestEvent();
        Map<String, String> headers =
                Map.of("Authorization", "11111111", "ip-address", TEST_IP_ADDRESS);
        event.setHeaders(headers);
        event.setPath(USER_IDENTITY_REQUEST);

        APIGatewayProxyResponseEvent response =
                buildUserIdentityHandler.handleRequest(event, mockContext);
        responseBody = OBJECT_MAPPER.readValue(response.getBody(), new TypeReference<>() {});

        assertEquals(
                BearerTokenError.INVALID_REQUEST.getHTTPStatusCode(), response.getStatusCode());
        assertEquals(BearerTokenError.INVALID_REQUEST.getCode(), responseBody.get("error"));
        assertEquals(
                BearerTokenError.INVALID_REQUEST.getDescription(),
                responseBody.get("error_description"));
        verify(mockClientOAuthSessionDetailsService, times(0)).getClientOAuthSession(any());
        verify(mockSessionCredentialsService, never()).deleteSessionCredentials(any());
    }

    @Test
    void shouldReturnErrorResponseWhenTokenIsMissing() throws Exception {
        APIGatewayProxyRequestEvent event = new APIGatewayProxyRequestEvent();
        Map<String, String> headers = Map.of("ip-address", TEST_IP_ADDRESS);
        event.setHeaders(headers);
        event.setPath(USER_IDENTITY_REQUEST);

        APIGatewayProxyResponseEvent response =
                buildUserIdentityHandler.handleRequest(event, mockContext);
        responseBody = OBJECT_MAPPER.readValue(response.getBody(), new TypeReference<>() {});

        assertEquals(BearerTokenError.MISSING_TOKEN.getHTTPStatusCode(), response.getStatusCode());
        assertEquals(BearerTokenError.MISSING_TOKEN.getCode(), responseBody.get("error"));
        assertEquals(
                BearerTokenError.MISSING_TOKEN.getDescription(),
                responseBody.get("error_description"));
        verify(mockClientOAuthSessionDetailsService, times(0)).getClientOAuthSession(any());
        verify(mockSessionCredentialsService, never()).deleteSessionCredentials(any());
    }

    @Test
    void shouldReturnErrorResponseWhenInvalidAccessTokenProvided() throws Exception {
        when(mockIpvSessionService.getIpvSessionByAccessToken(TEST_ACCESS_TOKEN))
                .thenThrow(new IpvSessionNotFoundException("error"));

        APIGatewayProxyResponseEvent response =
                buildUserIdentityHandler.handleRequest(testEvent, mockContext);
        Map<String, Object> responseBodyJson =
                OBJECT_MAPPER.readValue(response.getBody(), new TypeReference<>() {});

        assertEquals(403, response.getStatusCode());
        assertEquals(OAuth2Error.ACCESS_DENIED.getCode(), responseBodyJson.get("error"));
        assertEquals(
                OAuth2Error.ACCESS_DENIED
                        .appendDescription(
                                " - The supplied access token was not found in the database")
                        .getDescription(),
                responseBodyJson.get("error_description"));
        verify(mockClientOAuthSessionDetailsService, times(0)).getClientOAuthSession(any());
        verify(mockSessionCredentialsService, never()).deleteSessionCredentials(any());
    }

    @Test
    void shouldReturnErrorResponseWhenAccessTokenHasBeenRevoked() throws Exception {
        AccessTokenMetadata revokedAccessTokenMetadata = new AccessTokenMetadata();
        revokedAccessTokenMetadata.setRevokedAtDateTime(Instant.now().toString());
        ipvSessionItem.setAccessTokenMetadata(revokedAccessTokenMetadata);
        when(mockIpvSessionService.getIpvSessionByAccessToken(TEST_ACCESS_TOKEN))
                .thenReturn(ipvSessionItem);

        APIGatewayProxyResponseEvent response =
                buildUserIdentityHandler.handleRequest(testEvent, mockContext);
        responseBody = OBJECT_MAPPER.readValue(response.getBody(), new TypeReference<>() {});

        assertEquals(403, response.getStatusCode());
        assertEquals(OAuth2Error.ACCESS_DENIED.getCode(), responseBody.get("error"));
        assertEquals(
                OAuth2Error.ACCESS_DENIED
                        .appendDescription(" - The supplied access token has been revoked")
                        .getDescription(),
                responseBody.get("error_description"));
        verify(mockClientOAuthSessionDetailsService, times(0)).getClientOAuthSession(any());
        verify(mockSessionCredentialsService, never()).deleteSessionCredentials(any());
    }

    @Test
    void shouldReturn403ErrorResponseWhenAccessTokenHasExpired() throws Exception {
        AccessTokenMetadata expiredAccessTokenMetadata = new AccessTokenMetadata();
        expiredAccessTokenMetadata.setExpiryDateTime(Instant.now().minusSeconds(5).toString());
        ipvSessionItem.setAccessTokenMetadata(expiredAccessTokenMetadata);
        when(mockIpvSessionService.getIpvSessionByAccessToken(TEST_ACCESS_TOKEN))
                .thenReturn(ipvSessionItem);

        APIGatewayProxyResponseEvent response =
                buildUserIdentityHandler.handleRequest(testEvent, mockContext);
        responseBody = OBJECT_MAPPER.readValue(response.getBody(), new TypeReference<>() {});

        assertEquals(403, response.getStatusCode());
        assertEquals(OAuth2Error.ACCESS_DENIED.getCode(), responseBody.get("error"));
        assertEquals(
                OAuth2Error.ACCESS_DENIED
                        .appendDescription(" - The supplied access token has expired")
                        .getDescription(),
                responseBody.get("error_description"));
        verify(mockClientOAuthSessionDetailsService, times(0)).getClientOAuthSession(any());
        verify(mockSessionCredentialsService, never()).deleteSessionCredentials(any());
    }

    @Test
    void shouldReturn403ErrorResponseWhenIpvSessionNotFoundExceptionThrown() throws Exception {
        when(mockIpvSessionService.getIpvSessionByAccessToken(TEST_ACCESS_TOKEN))
                .thenThrow(new IpvSessionNotFoundException("err", new Exception()));

        APIGatewayProxyResponseEvent response =
                buildUserIdentityHandler.handleRequest(testEvent, mockContext);
        responseBody = OBJECT_MAPPER.readValue(response.getBody(), new TypeReference<>() {});

        assertEquals(403, response.getStatusCode());
        assertEquals(OAuth2Error.ACCESS_DENIED.getCode(), responseBody.get("error"));
        verify(mockClientOAuthSessionDetailsService, times(0)).getClientOAuthSession(any());
        verify(mockSessionCredentialsService, never()).deleteSessionCredentials(any());
    }

    @Test
    void shouldReturnErrorResponseOnUnrecognisedCiException() throws Exception {
        when(mockIpvSessionService.getIpvSessionByAccessToken(TEST_ACCESS_TOKEN))
                .thenReturn(ipvSessionItem);
        when(mockUserIdentityService.generateUserIdentity(any(), any(), any(), any(), any()))
                .thenThrow(new UnrecognisedCiException("This shouldn't really happen"));
        when(mockClientOAuthSessionDetailsService.getClientOAuthSession(any()))
                .thenReturn(clientOAuthSessionItem);

        APIGatewayProxyResponseEvent response =
                buildUserIdentityHandler.handleRequest(testEvent, mockContext);
        responseBody = OBJECT_MAPPER.readValue(response.getBody(), new TypeReference<>() {});

        assertEquals(500, response.getStatusCode());
        assertEquals("server_error", responseBody.get("error"));
        assertEquals(
                "Unexpected server error - CI error. This shouldn't really happen",
                responseBody.get("error_description"));
        verify(mockClientOAuthSessionDetailsService, times(1)).getClientOAuthSession(any());
        verify(mockUserIdentityService, times(1))
                .generateUserIdentity(any(), any(), any(), any(), any());
        verify(mockSessionCredentialsService, never()).deleteSessionCredentials(any());
    }

    @Test
    void shouldReturnErrorResponseOnSessionCredentialsReadFailure() throws Exception {
        when(mockIpvSessionService.getIpvSessionByAccessToken(TEST_ACCESS_TOKEN))
                .thenReturn(ipvSessionItem);
        when(mockSessionCredentialsService.getCredentials(TEST_IPV_SESSION_ID, TEST_USER_ID))
                .thenThrow(new VerifiableCredentialException(418, FAILED_TO_GET_CREDENTIAL));
        when(mockClientOAuthSessionDetailsService.getClientOAuthSession(any()))
                .thenReturn(clientOAuthSessionItem);

        APIGatewayProxyResponseEvent response =
                buildUserIdentityHandler.handleRequest(testEvent, mockContext);
        responseBody = OBJECT_MAPPER.readValue(response.getBody(), new TypeReference<>() {});

        assertEquals(418, response.getStatusCode());
        assertEquals(valueOf(FAILED_TO_GET_CREDENTIAL.getCode()), responseBody.get("error"));
        assertEquals(FAILED_TO_GET_CREDENTIAL.getMessage(), responseBody.get("error_description"));
        verify(mockUserIdentityService, never())
                .generateUserIdentity(any(), any(), any(), any(), any());
        verify(mockSessionCredentialsService, never()).deleteSessionCredentials(any());
    }

    @Test
    void shouldReturnErrorResponseWhenIpvSessionIsNull() throws Exception {
        when(mockIpvSessionService.getIpvSessionByAccessToken(TEST_ACCESS_TOKEN))
                .thenThrow(new IpvSessionNotFoundException("error"));

        APIGatewayProxyResponseEvent response =
                buildUserIdentityHandler.handleRequest(testEvent, mockContext);
        responseBody = OBJECT_MAPPER.readValue(response.getBody(), new TypeReference<>() {});

        assertEquals(403, response.getStatusCode());
        assertEquals(OAuth2Error.ACCESS_DENIED.getCode(), responseBody.get("error"));
        assertEquals(
                OAuth2Error.ACCESS_DENIED
                        .appendDescription(
                                " - The supplied access token was not found in the database")
                        .getDescription(),
                responseBody.get("error_description"));
        verify(mockUserIdentityService, never())
                .generateUserIdentity(any(), any(), any(), any(), any());
        verify(mockSessionCredentialsService, never()).deleteSessionCredentials(any());
    }

    @Test
    void shouldLogRuntimeExceptionsAndRethrow() throws Exception {
        // Arrange
        when(mockIpvSessionService.getIpvSessionByAccessToken(anyString()))
                .thenThrow(new RuntimeException("Test error"));

        var logCollector = LogCollector.getLogCollectorFor(BuildUserIdentityHandler.class);

        // Act
        var thrown =
                assertThrows(
                        Exception.class,
                        () -> buildUserIdentityHandler.handleRequest(testEvent, mockContext),
                        "Expected handleRequest() to throw, but it didn't");

        // Assert
        assertEquals("Test error", thrown.getMessage());
        var logMessage = logCollector.getLogMessages().get(0);
        assertThat(logMessage, containsString("Unhandled lambda exception"));
        assertThat(logMessage, containsString("Test error"));
    }

    private static APIGatewayProxyRequestEvent getEventWithAuthAndIpHeaders() {
        APIGatewayProxyRequestEvent event = new APIGatewayProxyRequestEvent();
        AccessToken accessToken = new BearerAccessToken(TEST_ACCESS_TOKEN);
        Map<String, String> headers =
                Map.of(
                        "Authorization",
                        accessToken.toAuthorizationHeader(),
                        "ip-address",
                        TEST_IP_ADDRESS);
        event.setHeaders(headers);
        event.setPath(USER_IDENTITY_REQUEST);
        return event;
    }

    private static ClientOAuthSessionItem getClientAuthSessionItemWithScope(String scope) {
        return ClientOAuthSessionItem.builder()
                .clientOAuthSessionId(TEST_CLIENT_OAUTH_SESSION_ID)
                .state("test-state")
                .responseType("code")
                .redirectUri("https://example.com/redirect")
                .govukSigninJourneyId("test-journey-id")
                .userId(TEST_USER_ID)
                .clientId("test-client")
                .govukSigninJourneyId("test-journey-id")
                .vtr(List.of("P2"))
                .scope(scope)
                .build();
    }

    private static ContraIndicator createCi(String code, List<String> issuers) {
        var ci = new ContraIndicator();
        ci.setCode(code);
        ci.setIssuers(
                issuers.stream()
                        .map(
                                iss -> {
                                    try {
                                        return new URI(iss);
                                    } catch (URISyntaxException e) {
                                        throw new RuntimeException(e); // Not expected in test setup
                                    }
                                })
                        .toList());
        return ci;
    }
}
