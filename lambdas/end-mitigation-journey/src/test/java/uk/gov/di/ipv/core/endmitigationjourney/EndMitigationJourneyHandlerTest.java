package uk.gov.di.ipv.core.endmitigationjourney;

import com.amazonaws.services.lambda.runtime.Context;
import com.amazonaws.services.lambda.runtime.events.APIGatewayProxyRequestEvent;
import com.amazonaws.services.lambda.runtime.events.APIGatewayProxyResponseEvent;
import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JOSEObjectType;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.crypto.ECDSASigner;
import com.nimbusds.jose.shaded.json.JSONObject;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.ArgumentCaptor;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import uk.gov.di.ipv.core.library.domain.ContraIndicatorItem;
import uk.gov.di.ipv.core.library.domain.gpg45.domain.CredentialEvidenceItem;
import uk.gov.di.ipv.core.library.dto.ContraIndicatorMitigationDetailsDto;
import uk.gov.di.ipv.core.library.dto.CredentialIssuerConfig;
import uk.gov.di.ipv.core.library.dto.MitigationJourneyDetailsDto;
import uk.gov.di.ipv.core.library.exceptions.CiPostMitigationsException;
import uk.gov.di.ipv.core.library.helpers.SecureTokenHelper;
import uk.gov.di.ipv.core.library.persistence.item.ClientOAuthSessionItem;
import uk.gov.di.ipv.core.library.persistence.item.IpvSessionItem;
import uk.gov.di.ipv.core.library.service.CiStorageService;
import uk.gov.di.ipv.core.library.service.ClientOAuthSessionDetailsService;
import uk.gov.di.ipv.core.library.service.ConfigService;
import uk.gov.di.ipv.core.library.service.IpvSessionService;
import uk.gov.di.ipv.core.library.service.UserIdentityService;

import java.net.URI;
import java.security.KeyFactory;
import java.security.NoSuchAlgorithmException;
import java.security.interfaces.ECPrivateKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.time.Instant;
import java.util.Base64;
import java.util.Collections;
import java.util.Date;
import java.util.List;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.doThrow;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;
import static uk.gov.di.ipv.core.library.fixtures.TestFixtures.EC_PRIVATE_KEY;
import static uk.gov.di.ipv.core.library.fixtures.TestFixtures.M1A_ADDRESS_VC;
import static uk.gov.di.ipv.core.library.fixtures.TestFixtures.M1A_PASSPORT_VC;
import static uk.gov.di.ipv.core.library.fixtures.TestFixtures.M1B_DCMAW_VC;
import static uk.gov.di.ipv.core.library.helpers.RequestHelper.IPV_SESSION_ID_HEADER;
import static uk.gov.di.ipv.core.library.helpers.RequestHelper.IP_ADDRESS_HEADER;

@ExtendWith(MockitoExtension.class)
class EndMitigationJourneyHandlerTest {
    private static final String TEST_IPV_SESSION_ID = SecureTokenHelper.generate();
    private static final String TEST_CLIENT_SOURCE_IP = "test-client-source-ip";
    private static final String TEST_CLIENT_OAUTH_SESSION_ID = SecureTokenHelper.generate();
    @Mock private IpvSessionService mockIpvSessionService;
    @Mock private UserIdentityService mockUserIdentityService;
    @Mock private CiStorageService mockCiStorageService;
    @Mock private ConfigService mockConfigService;
    @Mock private ClientOAuthSessionDetailsService mockClientOAuthSessionDetailsService;
    @Mock private Context mockContext;

    @InjectMocks
    private EndMitigationJourneyHandler endMitigationJourneyHandler =
            new EndMitigationJourneyHandler(
                    mockUserIdentityService,
                    mockIpvSessionService,
                    mockCiStorageService,
                    mockConfigService,
                    mockClientOAuthSessionDetailsService);

    private IpvSessionItem ipvSessionItem;
    private List<ContraIndicatorItem> contraIndicatorItems =
            List.of(
                    new ContraIndicatorItem(
                            "test-user-id",
                            "test-sort-key",
                            "test-iss",
                            Instant.now().minusSeconds(100).toString(),
                            "TEST-01",
                            "1234",
                            "1234"));
    private APIGatewayProxyRequestEvent event = new APIGatewayProxyRequestEvent();
    private ClientOAuthSessionItem clientOAuthSessionItem;

    @BeforeEach
    void setUp() {
        ipvSessionItem = new IpvSessionItem();
        ipvSessionItem.setIpvSessionId(TEST_IPV_SESSION_ID);
        ipvSessionItem.setUserState("test-state");
        ipvSessionItem.setClientOAuthSessionId(TEST_CLIENT_OAUTH_SESSION_ID);

        clientOAuthSessionItem =
                ClientOAuthSessionItem.builder()
                        .clientOAuthSessionId(TEST_CLIENT_OAUTH_SESSION_ID)
                        .state("test-state")
                        .responseType("code")
                        .redirectUri("https://example.com/redirect")
                        .govukSigninJourneyId("test-journey-id")
                        .userId("test-user-id")
                        .clientId("test-client")
                        .govukSigninJourneyId("test-journey-id")
                        .build();

        List<MitigationJourneyDetailsDto> mitigationJourneyDetails =
                List.of(new MitigationJourneyDetailsDto("MJ01", false));

        List<ContraIndicatorMitigationDetailsDto> contraIndicatorMitigationDetails =
                List.of(
                        new ContraIndicatorMitigationDetailsDto(
                                "TEST-01", mitigationJourneyDetails, true));
        ipvSessionItem.setContraIndicatorMitigationDetails(contraIndicatorMitigationDetails);

        event.setHeaders(
                Map.of(
                        IPV_SESSION_ID_HEADER,
                        TEST_IPV_SESSION_ID,
                        IP_ADDRESS_HEADER,
                        TEST_CLIENT_SOURCE_IP));
    }

    @Test
    void shouldSendPostMitigationRequestWhenMJ01JourneyAndHasFraudVC() throws Exception {
        when(mockIpvSessionService.getIpvSession(any())).thenReturn(ipvSessionItem);
        when(mockCiStorageService.getCIs(any(), any(), any())).thenReturn(contraIndicatorItems);
        when(mockConfigService.getCredentialIssuerActiveConnectionConfig(any()))
                .thenReturn(getTestFraudCriConfig());
        when(mockClientOAuthSessionDetailsService.getClientOAuthSession(any()))
                .thenReturn(clientOAuthSessionItem);

        List<String> credentials =
                List.of(
                        M1A_PASSPORT_VC,
                        M1A_ADDRESS_VC,
                        generateTestVc(
                                        "test-fraud-iss",
                                        Instant.now().minusSeconds(101).toEpochMilli(),
                                        List.of("TEST-01"))
                                .serialize(),
                        generateTestVc(
                                        "test-fraud-iss",
                                        Instant.now().toEpochMilli(),
                                        Collections.emptyList())
                                .serialize());
        when(mockUserIdentityService.getUserIssuedCredentials(any())).thenReturn(credentials);

        event.setPathParameters(Map.of("mitigationId", "MJ01"));

        APIGatewayProxyResponseEvent response =
                endMitigationJourneyHandler.handleRequest(event, mockContext);

        ArgumentCaptor<List<String>> mitigatingVcsArguementCaptor =
                ArgumentCaptor.forClass(List.class);
        verify(mockCiStorageService)
                .submitMitigatingVcList(mitigatingVcsArguementCaptor.capture(), any(), any());

        List<String> mitigatingVs = mitigatingVcsArguementCaptor.getValue();
        SignedJWT signedJWT = SignedJWT.parse(mitigatingVs.get(0));

        assertEquals("test-fraud-iss", signedJWT.getJWTClaimsSet().getIssuer());

        ArgumentCaptor<IpvSessionItem> ipvSessionItemArgumentCaptor =
                ArgumentCaptor.forClass(IpvSessionItem.class);

        verify(mockIpvSessionService).updateIpvSession(ipvSessionItemArgumentCaptor.capture());
        IpvSessionItem updatedSession = ipvSessionItemArgumentCaptor.getValue();
        MitigationJourneyDetailsDto mitigationJourneyDetails =
                updatedSession
                        .getContraIndicatorMitigationDetails()
                        .get(0)
                        .getMitigationJourneys()
                        .get(0);
        assertEquals("MJ01", mitigationJourneyDetails.getMitigationJourneyId());
        assertTrue(mitigationJourneyDetails.isComplete());
        verify(mockClientOAuthSessionDetailsService, times(1)).getClientOAuthSession(any());
    }

    @Test
    void shouldSendPostMitigationRequestWhenMJ02JourneyAndHasDcmawVC() throws Exception {
        List<MitigationJourneyDetailsDto> sessionMitigationJourneyDetails =
                List.of(
                        new MitigationJourneyDetailsDto("MJ01", true),
                        new MitigationJourneyDetailsDto("MJ02", false));

        List<ContraIndicatorMitigationDetailsDto> contraIndicatorMitigationDetails =
                List.of(
                        new ContraIndicatorMitigationDetailsDto(
                                "TEST-01", sessionMitigationJourneyDetails, true));
        ipvSessionItem.setContraIndicatorMitigationDetails(contraIndicatorMitigationDetails);

        when(mockIpvSessionService.getIpvSession(any())).thenReturn(ipvSessionItem);
        when(mockCiStorageService.getCIs(any(), any(), any())).thenReturn(contraIndicatorItems);

        List<String> credentials =
                List.of(
                        M1B_DCMAW_VC,
                        M1A_ADDRESS_VC,
                        generateTestVc(
                                        "test-fraud-iss",
                                        Instant.now().minusSeconds(101).toEpochMilli(),
                                        List.of("TEST-01"))
                                .serialize());
        when(mockUserIdentityService.getUserIssuedCredentials(any())).thenReturn(credentials);
        when(mockClientOAuthSessionDetailsService.getClientOAuthSession(any()))
                .thenReturn(clientOAuthSessionItem);

        event.setPathParameters(Map.of("mitigationId", "MJ02"));

        APIGatewayProxyResponseEvent response =
                endMitigationJourneyHandler.handleRequest(event, mockContext);

        ArgumentCaptor<List<String>> mitigatingVcsArguementCaptor =
                ArgumentCaptor.forClass(List.class);
        verify(mockCiStorageService)
                .submitMitigatingVcList(mitigatingVcsArguementCaptor.capture(), any(), any());

        List<String> mitigatingVs = mitigatingVcsArguementCaptor.getValue();
        SignedJWT signedJWT = SignedJWT.parse(mitigatingVs.get(0));

        assertEquals("test-dcmaw-iss", signedJWT.getJWTClaimsSet().getIssuer());

        ArgumentCaptor<IpvSessionItem> ipvSessionItemArgumentCaptor =
                ArgumentCaptor.forClass(IpvSessionItem.class);

        verify(mockIpvSessionService).updateIpvSession(ipvSessionItemArgumentCaptor.capture());
        IpvSessionItem updatedSession = ipvSessionItemArgumentCaptor.getValue();
        MitigationJourneyDetailsDto mitigationJourneyDetails =
                updatedSession
                        .getContraIndicatorMitigationDetails()
                        .get(0)
                        .getMitigationJourneys()
                        .get(1);
        assertEquals("MJ02", mitigationJourneyDetails.getMitigationJourneyId());
        assertTrue(mitigationJourneyDetails.isComplete());
        verify(mockClientOAuthSessionDetailsService, times(1)).getClientOAuthSession(any());
    }

    @Test
    void shouldNotSendPostMitigationRequestWhenMJ01JourneyAndMissingNewFraudVC() throws Exception {
        when(mockIpvSessionService.getIpvSession(any())).thenReturn(ipvSessionItem);
        when(mockCiStorageService.getCIs(any(), any(), any())).thenReturn(contraIndicatorItems);
        when(mockConfigService.getCredentialIssuerActiveConnectionConfig(any()))
                .thenReturn(getTestFraudCriConfig());

        List<String> credentials =
                List.of(
                        M1A_PASSPORT_VC,
                        M1A_ADDRESS_VC,
                        generateTestVc(
                                        "test-fraud-iss",
                                        Instant.now().minusSeconds(101).toEpochMilli(),
                                        List.of("TEST-01"))
                                .serialize());
        when(mockUserIdentityService.getUserIssuedCredentials(any())).thenReturn(credentials);
        when(mockClientOAuthSessionDetailsService.getClientOAuthSession(any()))
                .thenReturn(clientOAuthSessionItem);

        event.setPathParameters(Map.of("mitigationId", "MJ01"));

        APIGatewayProxyResponseEvent response =
                endMitigationJourneyHandler.handleRequest(event, mockContext);

        ArgumentCaptor<List<String>> mitigatingVcsArguementCaptor =
                ArgumentCaptor.forClass(List.class);
        verify(mockCiStorageService, times(0))
                .submitMitigatingVcList(mitigatingVcsArguementCaptor.capture(), any(), any());

        ArgumentCaptor<IpvSessionItem> ipvSessionItemArgumentCaptor =
                ArgumentCaptor.forClass(IpvSessionItem.class);

        verify(mockIpvSessionService).updateIpvSession(ipvSessionItemArgumentCaptor.capture());
        IpvSessionItem updatedSession = ipvSessionItemArgumentCaptor.getValue();
        MitigationJourneyDetailsDto mitigationJourneyDetails =
                updatedSession
                        .getContraIndicatorMitigationDetails()
                        .get(0)
                        .getMitigationJourneys()
                        .get(0);
        assertEquals("MJ01", mitigationJourneyDetails.getMitigationJourneyId());
        assertTrue(mitigationJourneyDetails.isComplete());
        verify(mockClientOAuthSessionDetailsService, times(1)).getClientOAuthSession(any());
    }

    @Test
    void shouldNotSendPostMitigationRequestWhenMJ02JourneyAndMissingDcmawVC() throws Exception {
        List<MitigationJourneyDetailsDto> sessionMitigationJourneyDetails =
                List.of(
                        new MitigationJourneyDetailsDto("MJ01", true),
                        new MitigationJourneyDetailsDto("MJ02", false));

        List<ContraIndicatorMitigationDetailsDto> contraIndicatorMitigationDetails =
                List.of(
                        new ContraIndicatorMitigationDetailsDto(
                                "TEST-01", sessionMitigationJourneyDetails, true));
        ipvSessionItem.setContraIndicatorMitigationDetails(contraIndicatorMitigationDetails);

        when(mockIpvSessionService.getIpvSession(any())).thenReturn(ipvSessionItem);
        when(mockCiStorageService.getCIs(any(), any(), any())).thenReturn(contraIndicatorItems);

        List<String> credentials =
                List.of(
                        M1A_PASSPORT_VC,
                        M1A_ADDRESS_VC,
                        generateTestVc(
                                        "test-fraud-iss",
                                        Instant.now().minusSeconds(101).toEpochMilli(),
                                        List.of("TEST-01"))
                                .serialize());
        when(mockUserIdentityService.getUserIssuedCredentials(any())).thenReturn(credentials);
        when(mockClientOAuthSessionDetailsService.getClientOAuthSession(any()))
                .thenReturn(clientOAuthSessionItem);

        event.setPathParameters(Map.of("mitigationId", "MJ02"));

        APIGatewayProxyResponseEvent response =
                endMitigationJourneyHandler.handleRequest(event, mockContext);

        ArgumentCaptor<List<String>> mitigatingVcsArguementCaptor =
                ArgumentCaptor.forClass(List.class);
        verify(mockCiStorageService, times(0))
                .submitMitigatingVcList(mitigatingVcsArguementCaptor.capture(), any(), any());

        ArgumentCaptor<IpvSessionItem> ipvSessionItemArgumentCaptor =
                ArgumentCaptor.forClass(IpvSessionItem.class);

        verify(mockIpvSessionService).updateIpvSession(ipvSessionItemArgumentCaptor.capture());
        IpvSessionItem updatedSession = ipvSessionItemArgumentCaptor.getValue();
        MitigationJourneyDetailsDto mitigationJourneyDetails =
                updatedSession
                        .getContraIndicatorMitigationDetails()
                        .get(0)
                        .getMitigationJourneys()
                        .get(1);
        assertEquals("MJ02", mitigationJourneyDetails.getMitigationJourneyId());
        assertTrue(mitigationJourneyDetails.isComplete());
        verify(mockClientOAuthSessionDetailsService, times(1)).getClientOAuthSession(any());
    }

    @Test
    void shouldNotSendPostMitigationRequestWhenMJ01JourneyAndNewFraudVcStillContainsCI()
            throws Exception {
        when(mockIpvSessionService.getIpvSession(any())).thenReturn(ipvSessionItem);
        when(mockCiStorageService.getCIs(any(), any(), any())).thenReturn(contraIndicatorItems);
        when(mockConfigService.getCredentialIssuerActiveConnectionConfig(any()))
                .thenReturn(getTestFraudCriConfig());

        List<String> credentials =
                List.of(
                        M1A_PASSPORT_VC,
                        M1A_ADDRESS_VC,
                        generateTestVc(
                                        "test-fraud-iss",
                                        Instant.now().minusSeconds(101).toEpochMilli(),
                                        List.of("TEST-01"))
                                .serialize(),
                        generateTestVc(
                                        "test-fraud-iss",
                                        Instant.now().toEpochMilli(),
                                        List.of("TEST-01"))
                                .serialize());
        when(mockUserIdentityService.getUserIssuedCredentials(any())).thenReturn(credentials);
        when(mockClientOAuthSessionDetailsService.getClientOAuthSession(any()))
                .thenReturn(clientOAuthSessionItem);

        event.setPathParameters(Map.of("mitigationId", "MJ01"));

        APIGatewayProxyResponseEvent response =
                endMitigationJourneyHandler.handleRequest(event, mockContext);

        ArgumentCaptor<List<String>> mitigatingVcsArguementCaptor =
                ArgumentCaptor.forClass(List.class);
        verify(mockCiStorageService, times(0))
                .submitMitigatingVcList(mitigatingVcsArguementCaptor.capture(), any(), any());

        ArgumentCaptor<IpvSessionItem> ipvSessionItemArgumentCaptor =
                ArgumentCaptor.forClass(IpvSessionItem.class);

        verify(mockIpvSessionService).updateIpvSession(ipvSessionItemArgumentCaptor.capture());
        IpvSessionItem updatedSession = ipvSessionItemArgumentCaptor.getValue();
        MitigationJourneyDetailsDto mitigationJourneyDetails =
                updatedSession
                        .getContraIndicatorMitigationDetails()
                        .get(0)
                        .getMitigationJourneys()
                        .get(0);
        assertEquals("MJ01", mitigationJourneyDetails.getMitigationJourneyId());
        assertTrue(mitigationJourneyDetails.isComplete());
        verify(mockClientOAuthSessionDetailsService, times(1)).getClientOAuthSession(any());
    }

    @Test
    void shouldNotSendPostMitigationRequestWhenMJ01JourneyAndFraudVcIsBeforeCI() throws Exception {
        when(mockIpvSessionService.getIpvSession(any())).thenReturn(ipvSessionItem);
        when(mockCiStorageService.getCIs(any(), any(), any())).thenReturn(contraIndicatorItems);
        when(mockConfigService.getCredentialIssuerActiveConnectionConfig(any()))
                .thenReturn(getTestFraudCriConfig());

        List<String> credentials =
                List.of(
                        M1A_PASSPORT_VC,
                        M1A_ADDRESS_VC,
                        generateTestVc(
                                        "test-fraud-iss",
                                        Instant.now().minusSeconds(101).toEpochMilli(),
                                        List.of("TEST-01"))
                                .serialize(),
                        generateTestVc(
                                        "test-fraud-iss",
                                        Instant.now().minusSeconds(201).toEpochMilli(),
                                        List.of())
                                .serialize());
        when(mockUserIdentityService.getUserIssuedCredentials(any())).thenReturn(credentials);
        when(mockClientOAuthSessionDetailsService.getClientOAuthSession(any()))
                .thenReturn(clientOAuthSessionItem);

        event.setPathParameters(Map.of("mitigationId", "MJ01"));

        APIGatewayProxyResponseEvent response =
                endMitigationJourneyHandler.handleRequest(event, mockContext);

        verify(mockCiStorageService, times(0)).submitMitigatingVcList(any(), any(), any());

        ArgumentCaptor<IpvSessionItem> ipvSessionItemArgumentCaptor =
                ArgumentCaptor.forClass(IpvSessionItem.class);

        verify(mockIpvSessionService).updateIpvSession(ipvSessionItemArgumentCaptor.capture());
        IpvSessionItem updatedSession = ipvSessionItemArgumentCaptor.getValue();
        MitigationJourneyDetailsDto mitigationJourneyDetails =
                updatedSession
                        .getContraIndicatorMitigationDetails()
                        .get(0)
                        .getMitigationJourneys()
                        .get(0);
        assertEquals("MJ01", mitigationJourneyDetails.getMitigationJourneyId());
        assertTrue(mitigationJourneyDetails.isComplete());
        verify(mockClientOAuthSessionDetailsService, times(1)).getClientOAuthSession(any());
    }

    @Test
    void shouldNotSendPostMitigationRequestWhenMJ01JourneyCiDoesNotMatchInSession()
            throws Exception {
        when(mockIpvSessionService.getIpvSession(any())).thenReturn(ipvSessionItem);
        when(mockCiStorageService.getCIs(any(), any(), any())).thenReturn(Collections.emptyList());

        List<String> credentials =
                List.of(
                        M1A_PASSPORT_VC,
                        M1A_ADDRESS_VC,
                        generateTestVc(
                                        "test-fraud-iss",
                                        Instant.now().minusSeconds(101).toEpochMilli(),
                                        List.of("TEST-01"))
                                .serialize(),
                        generateTestVc(
                                        "test-fraud-iss",
                                        Instant.now().minusSeconds(201).toEpochMilli(),
                                        List.of())
                                .serialize());
        when(mockUserIdentityService.getUserIssuedCredentials(any())).thenReturn(credentials);
        when(mockClientOAuthSessionDetailsService.getClientOAuthSession(any()))
                .thenReturn(clientOAuthSessionItem);

        event.setPathParameters(Map.of("mitigationId", "MJ01"));

        APIGatewayProxyResponseEvent response =
                endMitigationJourneyHandler.handleRequest(event, mockContext);

        verify(mockCiStorageService, times(0)).submitMitigatingVcList(any(), any(), any());

        ArgumentCaptor<IpvSessionItem> ipvSessionItemArgumentCaptor =
                ArgumentCaptor.forClass(IpvSessionItem.class);

        verify(mockIpvSessionService).updateIpvSession(ipvSessionItemArgumentCaptor.capture());
        IpvSessionItem updatedSession = ipvSessionItemArgumentCaptor.getValue();
        MitigationJourneyDetailsDto mitigationJourneyDetails =
                updatedSession
                        .getContraIndicatorMitigationDetails()
                        .get(0)
                        .getMitigationJourneys()
                        .get(0);
        assertEquals("MJ01", mitigationJourneyDetails.getMitigationJourneyId());
        assertTrue(mitigationJourneyDetails.isComplete());
        verify(mockClientOAuthSessionDetailsService, times(1)).getClientOAuthSession(any());
    }

    @Test
    void shouldStillUpdateSessionWhenSendPostMitigationRequestThrowsException() throws Exception {
        when(mockIpvSessionService.getIpvSession(any())).thenReturn(ipvSessionItem);
        when(mockCiStorageService.getCIs(any(), any(), any())).thenReturn(contraIndicatorItems);
        doThrow(new CiPostMitigationsException("test error"))
                .when(mockCiStorageService)
                .submitMitigatingVcList(any(), any(), any());
        when(mockConfigService.getCredentialIssuerActiveConnectionConfig(any()))
                .thenReturn(getTestFraudCriConfig());

        List<String> credentials =
                List.of(
                        M1A_PASSPORT_VC,
                        M1A_ADDRESS_VC,
                        generateTestVc(
                                        "test-fraud-iss",
                                        Instant.now().minusSeconds(101).toEpochMilli(),
                                        List.of("TEST-01"))
                                .serialize(),
                        generateTestVc(
                                        "test-fraud-iss",
                                        Instant.now().toEpochMilli(),
                                        Collections.emptyList())
                                .serialize());
        when(mockUserIdentityService.getUserIssuedCredentials(any())).thenReturn(credentials);
        when(mockClientOAuthSessionDetailsService.getClientOAuthSession(any()))
                .thenReturn(clientOAuthSessionItem);

        event.setPathParameters(Map.of("mitigationId", "MJ01"));

        APIGatewayProxyResponseEvent response =
                endMitigationJourneyHandler.handleRequest(event, mockContext);

        ArgumentCaptor<List<String>> mitigatingVcsArguementCaptor =
                ArgumentCaptor.forClass(List.class);
        verify(mockCiStorageService)
                .submitMitigatingVcList(mitigatingVcsArguementCaptor.capture(), any(), any());

        List<String> mitigatingVs = mitigatingVcsArguementCaptor.getValue();
        SignedJWT signedJWT = SignedJWT.parse(mitigatingVs.get(0));

        assertEquals("test-fraud-iss", signedJWT.getJWTClaimsSet().getIssuer());

        ArgumentCaptor<IpvSessionItem> ipvSessionItemArgumentCaptor =
                ArgumentCaptor.forClass(IpvSessionItem.class);

        verify(mockIpvSessionService).updateIpvSession(ipvSessionItemArgumentCaptor.capture());
        IpvSessionItem updatedSession = ipvSessionItemArgumentCaptor.getValue();
        MitigationJourneyDetailsDto mitigationJourneyDetails =
                updatedSession
                        .getContraIndicatorMitigationDetails()
                        .get(0)
                        .getMitigationJourneys()
                        .get(0);
        assertEquals("MJ01", mitigationJourneyDetails.getMitigationJourneyId());
        assertTrue(mitigationJourneyDetails.isComplete());
        verify(mockClientOAuthSessionDetailsService, times(1)).getClientOAuthSession(any());
    }

    @Test
    void shouldNotUpdateSessionIfMitigationJourneyIdIsUnknown() throws Exception {
        when(mockIpvSessionService.getIpvSession(any())).thenReturn(ipvSessionItem);
        when(mockCiStorageService.getCIs(any(), any(), any())).thenReturn(contraIndicatorItems);

        List<String> credentials =
                List.of(
                        M1A_PASSPORT_VC,
                        M1A_ADDRESS_VC,
                        generateTestVc(
                                        "test-fraud-iss",
                                        Instant.now().minusSeconds(101).toEpochMilli(),
                                        List.of("TEST-01"))
                                .serialize(),
                        generateTestVc(
                                        "test-fraud-iss",
                                        Instant.now().toEpochMilli(),
                                        Collections.emptyList())
                                .serialize());
        when(mockUserIdentityService.getUserIssuedCredentials(any())).thenReturn(credentials);
        when(mockClientOAuthSessionDetailsService.getClientOAuthSession(any()))
                .thenReturn(clientOAuthSessionItem);

        event.setPathParameters(Map.of("mitigationId", "unknown"));

        APIGatewayProxyResponseEvent response =
                endMitigationJourneyHandler.handleRequest(event, mockContext);
        verify(mockCiStorageService, times(0)).submitMitigatingVcList(any(), any(), any());
        verify(mockIpvSessionService, times(0)).updateIpvSession(any());
        verify(mockClientOAuthSessionDetailsService, times(1)).getClientOAuthSession(any());
    }

    @Test
    void shouldUpdateSessionAndCompleteCorrectMitigationJourney() throws Exception {
        List<MitigationJourneyDetailsDto> testMitigationJourneyDetails =
                List.of(
                        new MitigationJourneyDetailsDto("MJ01", false),
                        new MitigationJourneyDetailsDto("MJ02", false));

        List<ContraIndicatorMitigationDetailsDto> testContraIndicatorMitigationDetails =
                List.of(
                        new ContraIndicatorMitigationDetailsDto(
                                "TEST-01", testMitigationJourneyDetails, true));

        ipvSessionItem.setContraIndicatorMitigationDetails(testContraIndicatorMitigationDetails);

        when(mockIpvSessionService.getIpvSession(any())).thenReturn(ipvSessionItem);
        when(mockCiStorageService.getCIs(any(), any(), any())).thenReturn(contraIndicatorItems);
        when(mockConfigService.getCredentialIssuerActiveConnectionConfig(any()))
                .thenReturn(getTestFraudCriConfig());

        List<String> credentials =
                List.of(
                        M1A_PASSPORT_VC,
                        M1A_ADDRESS_VC,
                        generateTestVc(
                                        "test-fraud-iss",
                                        Instant.now().minusSeconds(101).toEpochMilli(),
                                        List.of("TEST-01"))
                                .serialize(),
                        generateTestVc(
                                        "test-fraud-iss",
                                        Instant.now().toEpochMilli(),
                                        Collections.emptyList())
                                .serialize());
        when(mockUserIdentityService.getUserIssuedCredentials(any())).thenReturn(credentials);
        when(mockClientOAuthSessionDetailsService.getClientOAuthSession(any()))
                .thenReturn(clientOAuthSessionItem);

        event.setPathParameters(Map.of("mitigationId", "MJ01"));

        APIGatewayProxyResponseEvent response =
                endMitigationJourneyHandler.handleRequest(event, mockContext);

        ArgumentCaptor<List<String>> mitigatingVcsArguementCaptor =
                ArgumentCaptor.forClass(List.class);
        verify(mockCiStorageService)
                .submitMitigatingVcList(mitigatingVcsArguementCaptor.capture(), any(), any());

        List<String> mitigatingVs = mitigatingVcsArguementCaptor.getValue();
        SignedJWT signedJWT = SignedJWT.parse(mitigatingVs.get(0));

        assertEquals("test-fraud-iss", signedJWT.getJWTClaimsSet().getIssuer());

        ArgumentCaptor<IpvSessionItem> ipvSessionItemArgumentCaptor =
                ArgumentCaptor.forClass(IpvSessionItem.class);

        verify(mockIpvSessionService).updateIpvSession(ipvSessionItemArgumentCaptor.capture());
        IpvSessionItem updatedSession = ipvSessionItemArgumentCaptor.getValue();
        MitigationJourneyDetailsDto mitigationJourneyDetails =
                updatedSession
                        .getContraIndicatorMitigationDetails()
                        .get(0)
                        .getMitigationJourneys()
                        .get(0);
        assertEquals("MJ01", mitigationJourneyDetails.getMitigationJourneyId());
        assertTrue(mitigationJourneyDetails.isComplete());
        verify(mockClientOAuthSessionDetailsService, times(1)).getClientOAuthSession(any());
    }

    private CredentialIssuerConfig getTestFraudCriConfig() {
        return new CredentialIssuerConfig(
                URI.create("http://example.com/token"),
                URI.create("http://example.com/credential"),
                URI.create("http://example.com/authorize"),
                "ipv-core",
                "test-jwk",
                "test-jwk",
                "test-fraud-iss",
                URI.create("http://example.com/callback"),
                true);
    }

    private SignedJWT generateTestVc(String iss, long nbf, List<String> cis)
            throws InvalidKeySpecException, NoSuchAlgorithmException, JOSEException {
        JSONObject vcClaim = new JSONObject();
        List<CredentialEvidenceItem> credentialEvidenceList =
                List.of(
                        new CredentialEvidenceItem(
                                CredentialEvidenceItem.EvidenceType.IDENTITY_FRAUD, 2, cis));
        vcClaim.appendField("evidence", credentialEvidenceList);

        JWTClaimsSet jwtClaimsSet =
                new JWTClaimsSet.Builder()
                        .issuer(iss)
                        .notBeforeTime(new Date(nbf))
                        .claim("vc", vcClaim)
                        .build();
        SignedJWT signedJWT =
                new SignedJWT(
                        new JWSHeader.Builder(JWSAlgorithm.ES256).type(JOSEObjectType.JWT).build(),
                        jwtClaimsSet);
        signedJWT.sign(new ECDSASigner(getPrivateKey()));
        return signedJWT;
    }

    private static ECPrivateKey getPrivateKey()
            throws InvalidKeySpecException, NoSuchAlgorithmException {
        return (ECPrivateKey)
                KeyFactory.getInstance("EC")
                        .generatePrivate(
                                new PKCS8EncodedKeySpec(
                                        Base64.getDecoder().decode(EC_PRIVATE_KEY)));
    }
}
