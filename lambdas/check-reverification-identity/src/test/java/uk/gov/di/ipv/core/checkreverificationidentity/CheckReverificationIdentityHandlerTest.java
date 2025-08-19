package uk.gov.di.ipv.core.checkreverificationidentity;

import com.amazonaws.services.lambda.runtime.Context;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import uk.gov.di.ipv.core.library.domain.JourneyRequest;
import uk.gov.di.ipv.core.library.domain.VerifiableCredential;
import uk.gov.di.ipv.core.library.evcs.exception.EvcsServiceException;
import uk.gov.di.ipv.core.library.evcs.service.EvcsService;
import uk.gov.di.ipv.core.library.exceptions.ClientOauthSessionNotFoundException;
import uk.gov.di.ipv.core.library.exceptions.CredentialParseException;
import uk.gov.di.ipv.core.library.exceptions.HttpResponseExceptionWithErrorBody;
import uk.gov.di.ipv.core.library.exceptions.IpvSessionNotFoundException;
import uk.gov.di.ipv.core.library.gpg45.Gpg45Scores;
import uk.gov.di.ipv.core.library.persistence.item.ClientOAuthSessionItem;
import uk.gov.di.ipv.core.library.persistence.item.IpvSessionItem;
import uk.gov.di.ipv.core.library.service.ClientOAuthSessionDetailsService;
import uk.gov.di.ipv.core.library.service.ConfigService;
import uk.gov.di.ipv.core.library.service.IpvSessionService;
import uk.gov.di.ipv.core.library.testhelpers.unit.LogCollector;
import uk.gov.di.ipv.core.library.useridentity.service.UserIdentityService;
import uk.gov.di.ipv.core.library.useridentity.service.VotMatcher;
import uk.gov.di.ipv.core.library.useridentity.service.VotMatchingResult;

import java.util.List;
import java.util.Optional;

import static com.nimbusds.oauth2.sdk.http.HTTPResponse.SC_NOT_FOUND;
import static com.nimbusds.oauth2.sdk.http.HTTPResponse.SC_SERVER_ERROR;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.inOrder;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.spy;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;
import static uk.gov.di.ipv.core.library.domain.ErrorResponse.CLIENT_OAUTH_SESSION_NOT_FOUND;
import static uk.gov.di.ipv.core.library.domain.ErrorResponse.FAILED_NAME_CORRELATION;
import static uk.gov.di.ipv.core.library.domain.ErrorResponse.FAILED_TO_PARSE_SUCCESSFUL_VC_STORE_ITEMS;
import static uk.gov.di.ipv.core.library.domain.ErrorResponse.IPV_SESSION_NOT_FOUND;
import static uk.gov.di.ipv.core.library.domain.ErrorResponse.RECEIVED_NON_200_RESPONSE_STATUS_CODE;
import static uk.gov.di.ipv.core.library.domain.ReverificationFailureCode.NO_IDENTITY_AVAILABLE;
import static uk.gov.di.ipv.core.library.enums.Vot.P1;
import static uk.gov.di.ipv.core.library.enums.Vot.P2;
import static uk.gov.di.ipv.core.library.enums.Vot.SUPPORTED_VOTS_BY_DESCENDING_STRENGTH;
import static uk.gov.di.ipv.core.library.evcs.enums.EvcsVCState.CURRENT;
import static uk.gov.di.ipv.core.library.fixtures.VcFixtures.vcAddressOne;
import static uk.gov.di.ipv.core.library.fixtures.VcFixtures.vcDcmawDrivingPermitDvaM1b;
import static uk.gov.di.ipv.core.library.fixtures.VcFixtures.vcExperianFraudScoreTwo;
import static uk.gov.di.ipv.core.library.fixtures.VcFixtures.vcExperianKbvM1a;
import static uk.gov.di.ipv.core.library.fixtures.VcFixtures.vcNinoIdentityCheckL1a;
import static uk.gov.di.ipv.core.library.gpg45.enums.Gpg45Profile.L1A;
import static uk.gov.di.ipv.core.library.gpg45.enums.Gpg45Profile.M1A;

@ExtendWith(MockitoExtension.class)
class CheckReverificationIdentityHandlerTest {
    private static final List<uk.gov.di.model.ContraIndicator> EMPTY_CONTRA_INDICATORS = List.of();
    private static final String TEST_IPV_SESSION_ID = "test-ipv-session-id";
    private static final String TEST_CLIENT_SESSION_ID = "test-client-session-id";
    private static final String TEST_USER_ID = "test-user-id";
    private static final String TEST_EVCS_ACCESS_TOKEN = "test-evcs-access-token";
    private static final JourneyRequest REQUEST =
            JourneyRequest.builder().ipvSessionId(TEST_IPV_SESSION_ID).build();
    private static VerifiableCredential m1BFraudVc;
    private static VerifiableCredential l1AEvidenceVc;
    private static VerifiableCredential m1AVerificationVc;
    private IpvSessionItem ipvSession;
    private ClientOAuthSessionItem clientSession;

    @Mock private Context mockContext;
    @Mock private ConfigService mockConfigService;
    @Mock private IpvSessionService mockIpvSessionService;
    @Mock private ClientOAuthSessionDetailsService mockClientSessionService;
    @Mock private EvcsService mockEvcsService;
    @Mock private UserIdentityService mockUserIdentityService;
    @Mock private VotMatcher mockVotMatcher;
    @InjectMocks private CheckReverificationIdentityHandler checkReverificationIdentityHandler;

    @BeforeAll
    static void beforeAll() {
        m1BFraudVc = vcExperianFraudScoreTwo();
        l1AEvidenceVc = vcNinoIdentityCheckL1a();
        m1AVerificationVc = vcExperianKbvM1a();
    }

    @BeforeEach
    void beforeEach() {
        ipvSession =
                spy(
                        IpvSessionItem.builder()
                                .ipvSessionId(TEST_IPV_SESSION_ID)
                                .clientOAuthSessionId(TEST_CLIENT_SESSION_ID)
                                .build());
        clientSession =
                ClientOAuthSessionItem.builder()
                        .clientOAuthSessionId(TEST_CLIENT_SESSION_ID)
                        .userId(TEST_USER_ID)
                        .evcsAccessToken(TEST_EVCS_ACCESS_TOKEN)
                        .build();
    }

    @Nested
    class SuccessfulInvocations {
        @BeforeEach
        void beforeEachFound() throws Exception {
            when(mockIpvSessionService.getIpvSession(TEST_IPV_SESSION_ID)).thenReturn(ipvSession);
            when(mockClientSessionService.getClientOAuthSession(TEST_CLIENT_SESSION_ID))
                    .thenReturn(clientSession);
        }

        @Test
        void shouldReturnJourneyFoundIfUserHasP2Identity() throws Exception {
            var addressVc = vcAddressOne();
            var m1bDrivingPermitVc = vcDcmawDrivingPermitDvaM1b();
            var p2Vcs = List.of(m1bDrivingPermitVc, addressVc, m1BFraudVc);
            when(mockUserIdentityService.areVcsCorrelated(
                            List.of(m1bDrivingPermitVc, addressVc, m1BFraudVc)))
                    .thenReturn(true);
            when(mockEvcsService.getVerifiableCredentials(
                            TEST_USER_ID, TEST_EVCS_ACCESS_TOKEN, CURRENT))
                    .thenReturn(p2Vcs);
            when(mockVotMatcher.findStrongestMatches(
                            SUPPORTED_VOTS_BY_DESCENDING_STRENGTH,
                            p2Vcs,
                            EMPTY_CONTRA_INDICATORS,
                            true))
                    .thenReturn(
                            new VotMatchingResult(
                                    Optional.of(
                                            new VotMatchingResult.VotAndProfile(
                                                    P2, Optional.of(M1A))),
                                    Optional.of(
                                            new VotMatchingResult.VotAndProfile(
                                                    P2, Optional.of(M1A))),
                                    Gpg45Scores.builder().build()));

            var response = checkReverificationIdentityHandler.handleRequest(REQUEST, mockContext);

            assertEquals("/journey/found", response.get("journey"));

            verify(ipvSession, never()).setFailureCode(any());
        }

        @Test
        void shouldReturnJourneyFoundIfUserHasP1Identity() throws Exception {
            var p1Vcs = List.of(l1AEvidenceVc, vcAddressOne(), m1BFraudVc, m1AVerificationVc);
            when(mockUserIdentityService.areVcsCorrelated(p1Vcs)).thenReturn(true);
            when(mockEvcsService.getVerifiableCredentials(
                            TEST_USER_ID, TEST_EVCS_ACCESS_TOKEN, CURRENT))
                    .thenReturn(p1Vcs);
            when(mockVotMatcher.findStrongestMatches(
                            SUPPORTED_VOTS_BY_DESCENDING_STRENGTH,
                            p1Vcs,
                            EMPTY_CONTRA_INDICATORS,
                            true))
                    .thenReturn(
                            new VotMatchingResult(
                                    Optional.of(
                                            new VotMatchingResult.VotAndProfile(
                                                    P1, Optional.of(L1A))),
                                    Optional.of(
                                            new VotMatchingResult.VotAndProfile(
                                                    P1, Optional.of(L1A))),
                                    Gpg45Scores.builder().build()));

            var response = checkReverificationIdentityHandler.handleRequest(REQUEST, mockContext);

            assertEquals("/journey/found", response.get("journey"));

            verify(ipvSession, never()).setFailureCode(any());
        }

        @Test
        void shouldReturnJourneyNotFoundWhenNoVotMatched() {
            when(mockVotMatcher.findStrongestMatches(
                            SUPPORTED_VOTS_BY_DESCENDING_STRENGTH,
                            List.of(),
                            EMPTY_CONTRA_INDICATORS,
                            false))
                    .thenReturn(new VotMatchingResult(Optional.empty(), Optional.empty(), null));

            var response = checkReverificationIdentityHandler.handleRequest(REQUEST, mockContext);

            assertEquals("/journey/not-found", response.get("journey"));

            var inorder = inOrder(ipvSession, mockIpvSessionService);
            inorder.verify(ipvSession).setFailureCode(NO_IDENTITY_AVAILABLE);
            inorder.verify(mockIpvSessionService).updateIpvSession(ipvSession);
            inorder.verifyNoMoreInteractions();
        }
    }

    @Nested
    class ErrorInvocations {
        @Test
        void shouldReturnJourneyErrorIfIpvSessionNotFound() throws Exception {
            when(mockIpvSessionService.getIpvSession(TEST_IPV_SESSION_ID))
                    .thenThrow(new IpvSessionNotFoundException("Beep"));

            var response = checkReverificationIdentityHandler.handleRequest(REQUEST, mockContext);

            assertEquals("/journey/error", response.get("journey"));
            assertEquals(SC_NOT_FOUND, response.get("statusCode"));
            assertEquals(IPV_SESSION_NOT_FOUND.getMessage(), response.get("message"));
            verify(ipvSession, never()).setFailureCode(any());
        }

        @Test
        void shouldReturnJourneyErrorIfClientSessionIdNotFound() throws Exception {
            when(mockIpvSessionService.getIpvSession(TEST_IPV_SESSION_ID)).thenReturn(ipvSession);
            when(mockClientSessionService.getClientOAuthSession(TEST_CLIENT_SESSION_ID))
                    .thenThrow(new ClientOauthSessionNotFoundException());

            var response = checkReverificationIdentityHandler.handleRequest(REQUEST, mockContext);

            assertEquals("/journey/error", response.get("journey"));
            assertEquals(SC_SERVER_ERROR, response.get("statusCode"));
            assertEquals(CLIENT_OAUTH_SESSION_NOT_FOUND.getMessage(), response.get("message"));
            verify(ipvSession, never()).setFailureCode(any());
        }

        @Test
        void shouldReturnJourneyErrorIfErrorFetchingVcs() throws Exception {
            when(mockIpvSessionService.getIpvSession(TEST_IPV_SESSION_ID)).thenReturn(ipvSession);
            when(mockClientSessionService.getClientOAuthSession(TEST_CLIENT_SESSION_ID))
                    .thenReturn(clientSession);
            when(mockEvcsService.getVerifiableCredentials(
                            TEST_USER_ID, TEST_EVCS_ACCESS_TOKEN, CURRENT))
                    .thenThrow(
                            new EvcsServiceException(
                                    SC_SERVER_ERROR, RECEIVED_NON_200_RESPONSE_STATUS_CODE));

            var response = checkReverificationIdentityHandler.handleRequest(REQUEST, mockContext);

            assertEquals("/journey/error", response.get("journey"));
            assertEquals(SC_SERVER_ERROR, response.get("statusCode"));
            assertEquals(
                    RECEIVED_NON_200_RESPONSE_STATUS_CODE.getMessage(), response.get("message"));
            verify(ipvSession, never()).setFailureCode(any());
        }

        @Test
        void shouldReturnJourneyErrorIfFailureToParseFetchedVcs() throws Exception {
            when(mockIpvSessionService.getIpvSession(TEST_IPV_SESSION_ID)).thenReturn(ipvSession);
            when(mockClientSessionService.getClientOAuthSession(TEST_CLIENT_SESSION_ID))
                    .thenReturn(clientSession);
            when(mockEvcsService.getVerifiableCredentials(
                            TEST_USER_ID, TEST_EVCS_ACCESS_TOKEN, CURRENT))
                    .thenThrow(new CredentialParseException("Baa"));

            var response = checkReverificationIdentityHandler.handleRequest(REQUEST, mockContext);

            assertEquals("/journey/error", response.get("journey"));
            assertEquals(SC_SERVER_ERROR, response.get("statusCode"));
            assertEquals(
                    FAILED_TO_PARSE_SUCCESSFUL_VC_STORE_ITEMS.getMessage(),
                    response.get("message"));
            verify(ipvSession, never()).setFailureCode(any());
        }

        @Test
        void shouldReturnJourneyErrorIfFailureToDoCorrelationCheck() throws Exception {
            when(mockIpvSessionService.getIpvSession(TEST_IPV_SESSION_ID)).thenReturn(ipvSession);
            when(mockClientSessionService.getClientOAuthSession(TEST_CLIENT_SESSION_ID))
                    .thenReturn(clientSession);
            when(mockEvcsService.getVerifiableCredentials(
                            TEST_USER_ID, TEST_EVCS_ACCESS_TOKEN, CURRENT))
                    .thenReturn(List.of(m1BFraudVc));
            when(mockUserIdentityService.areVcsCorrelated(List.of(m1BFraudVc)))
                    .thenThrow(
                            new HttpResponseExceptionWithErrorBody(
                                    SC_SERVER_ERROR, FAILED_NAME_CORRELATION));

            var response = checkReverificationIdentityHandler.handleRequest(REQUEST, mockContext);

            assertEquals("/journey/error", response.get("journey"));
            assertEquals(SC_SERVER_ERROR, response.get("statusCode"));
            assertEquals(FAILED_NAME_CORRELATION.getMessage(), response.get("message"));
            verify(ipvSession, never()).setFailureCode(any());
        }

        @Test
        void shouldLogRuntimeExceptionsAndRethrow() throws Exception {
            when(mockIpvSessionService.getIpvSession(TEST_IPV_SESSION_ID))
                    .thenThrow(new RuntimeException("😓"));

            var logCollector =
                    LogCollector.getLogCollectorFor(CheckReverificationIdentityHandler.class);

            var thrown =
                    assertThrows(
                            RuntimeException.class,
                            () ->
                                    checkReverificationIdentityHandler.handleRequest(
                                            REQUEST, mockContext));

            assertEquals("😓", thrown.getMessage());

            var logMessage = logCollector.getLogMessages().get(0);
            assertTrue(logMessage.contains("Unhandled lambda exception"));
            assertTrue(logMessage.contains("😓"));
            verify(ipvSession, never()).setFailureCode(any());
        }
    }
}
