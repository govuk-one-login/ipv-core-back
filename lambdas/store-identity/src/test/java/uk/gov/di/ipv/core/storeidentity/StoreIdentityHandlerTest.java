package uk.gov.di.ipv.core.storeidentity;

import com.amazonaws.services.lambda.runtime.Context;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import uk.gov.di.ipv.core.library.domain.ProcessRequest;
import uk.gov.di.ipv.core.library.domain.VerifiableCredential;
import uk.gov.di.ipv.core.library.exceptions.VerifiableCredentialException;
import uk.gov.di.ipv.core.library.persistence.item.ClientOAuthSessionItem;
import uk.gov.di.ipv.core.library.persistence.item.IpvSessionItem;
import uk.gov.di.ipv.core.library.service.ClientOAuthSessionDetailsService;
import uk.gov.di.ipv.core.library.service.ConfigService;
import uk.gov.di.ipv.core.library.service.IpvSessionService;
import uk.gov.di.ipv.core.library.verifiablecredential.service.SessionCredentialsService;
import uk.gov.di.ipv.core.library.verifiablecredential.service.VerifiableCredentialService;

import java.util.List;

import static org.apache.http.HttpStatus.SC_BAD_REQUEST;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.doThrow;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;
import static uk.gov.di.ipv.core.library.domain.ErrorResponse.FAILED_TO_GET_CREDENTIAL;
import static uk.gov.di.ipv.core.library.domain.ErrorResponse.FAILED_TO_STORE_IDENTITY;
import static uk.gov.di.ipv.core.library.domain.ErrorResponse.MISSING_IPV_SESSION_ID;
import static uk.gov.di.ipv.core.library.fixtures.VcFixtures.EXPIRED_M1A_EXPERIAN_FRAUD_VC;
import static uk.gov.di.ipv.core.library.fixtures.VcFixtures.M1A_ADDRESS_VC;
import static uk.gov.di.ipv.core.library.fixtures.VcFixtures.PASSPORT_NON_DCMAW_SUCCESSFUL_VC;
import static uk.gov.di.ipv.core.library.journeyuris.JourneyUris.JOURNEY_ERROR_PATH;
import static uk.gov.di.ipv.core.library.journeyuris.JourneyUris.JOURNEY_IDENTITY_STORED_PATH;

@ExtendWith(MockitoExtension.class)
class StoreIdentityHandlerTest {
    private static final String SESSION_ID = "session-id";
    private static final String USER_ID = "user-id";
    private static final String CLIENT_SESSION_ID = "client-session-id";
    private static final String JOURNEY = "journey";
    private static final String STATUS_CODE = "statusCode";
    private static final String CODE = "code";
    private static final String MESSAGE = "message";
    private static IpvSessionItem ipvSessionItem;
    private static ClientOAuthSessionItem clientOAuthSessionItem;

    @Mock private Context mockContext;
    @Mock private ConfigService mockConfigService;
    @Mock private ClientOAuthSessionDetailsService mockClientOauthSessionDetailsService;
    @Mock private IpvSessionService mockIpvSessionService;
    @Mock private SessionCredentialsService mockSessionCredentialService;
    @Mock private VerifiableCredentialService mockVerifiableCredentialService;
    @InjectMocks private StoreIdentityHandler storeIdentityHandler;

    @BeforeAll
    static void setUp() {
        ipvSessionItem = new IpvSessionItem();
        ipvSessionItem.setIpvSessionId(SESSION_ID);
        ipvSessionItem.setClientOAuthSessionId(CLIENT_SESSION_ID);

        clientOAuthSessionItem = new ClientOAuthSessionItem();
        clientOAuthSessionItem.setUserId(USER_ID);
    }

    @Test
    void shouldReturnAnIdentityStoredJourney() throws Exception {
        when(mockIpvSessionService.getIpvSession(SESSION_ID)).thenReturn(ipvSessionItem);
        when(mockClientOauthSessionDetailsService.getClientOAuthSession(CLIENT_SESSION_ID))
                .thenReturn(clientOAuthSessionItem);
        List<VerifiableCredential> vcs =
                List.of(
                        PASSPORT_NON_DCMAW_SUCCESSFUL_VC,
                        EXPIRED_M1A_EXPERIAN_FRAUD_VC,
                        M1A_ADDRESS_VC);
        when(mockSessionCredentialService.getCredentials(SESSION_ID, USER_ID)).thenReturn(vcs);

        var response =
                storeIdentityHandler.handleRequest(
                        ProcessRequest.processRequestBuilder().ipvSessionId(SESSION_ID).build(),
                        mockContext);

        assertEquals(JOURNEY_IDENTITY_STORED_PATH, response.get(JOURNEY));
        verify(mockVerifiableCredentialService).storeIdentity(vcs, USER_ID);
    }

    @Test
    void shouldReturnAnErrorJourneyIfIpvSessionIdMissing() throws Exception {
        var response =
                storeIdentityHandler.handleRequest(
                        ProcessRequest.processRequestBuilder().build(), mockContext);

        assertEquals(JOURNEY_ERROR_PATH, response.get(JOURNEY));
        assertEquals(SC_BAD_REQUEST, response.get(STATUS_CODE));
        assertEquals(MISSING_IPV_SESSION_ID.getCode(), response.get(CODE));
        assertEquals(MISSING_IPV_SESSION_ID.getMessage(), response.get(MESSAGE));
        verify(mockVerifiableCredentialService, never()).storeIdentity(any(), any());
    }

    @Test
    void shouldReturnAnErrorJourneyIfCantFetchSessionCredentials() throws Exception {
        when(mockIpvSessionService.getIpvSession(SESSION_ID)).thenReturn(ipvSessionItem);
        when(mockClientOauthSessionDetailsService.getClientOAuthSession(CLIENT_SESSION_ID))
                .thenReturn(clientOAuthSessionItem);
        when(mockSessionCredentialService.getCredentials(SESSION_ID, USER_ID))
                .thenThrow(new VerifiableCredentialException(418, FAILED_TO_GET_CREDENTIAL));

        var response =
                storeIdentityHandler.handleRequest(
                        ProcessRequest.processRequestBuilder().ipvSessionId(SESSION_ID).build(),
                        mockContext);

        assertEquals(JOURNEY_ERROR_PATH, response.get(JOURNEY));
        assertEquals(418, response.get(STATUS_CODE));
        assertEquals(FAILED_TO_GET_CREDENTIAL.getCode(), response.get(CODE));
        assertEquals(FAILED_TO_GET_CREDENTIAL.getMessage(), response.get(MESSAGE));
        verify(mockVerifiableCredentialService, never()).storeIdentity(any(), any());
    }

    @Test
    void shouldReturnAnErrorJourneyIfCantStoreIdentity() throws Exception {
        when(mockIpvSessionService.getIpvSession(SESSION_ID)).thenReturn(ipvSessionItem);
        when(mockClientOauthSessionDetailsService.getClientOAuthSession(CLIENT_SESSION_ID))
                .thenReturn(clientOAuthSessionItem);
        doThrow(new VerifiableCredentialException(418, FAILED_TO_STORE_IDENTITY))
                .when(mockVerifiableCredentialService)
                .storeIdentity(any(), any());

        var response =
                storeIdentityHandler.handleRequest(
                        ProcessRequest.processRequestBuilder().ipvSessionId(SESSION_ID).build(),
                        mockContext);

        assertEquals(JOURNEY_ERROR_PATH, response.get(JOURNEY));
        assertEquals(418, response.get(STATUS_CODE));
        assertEquals(FAILED_TO_STORE_IDENTITY.getCode(), response.get(CODE));
        assertEquals(FAILED_TO_STORE_IDENTITY.getMessage(), response.get(MESSAGE));
    }
}
