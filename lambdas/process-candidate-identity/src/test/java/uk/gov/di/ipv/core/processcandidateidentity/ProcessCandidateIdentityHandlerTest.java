package uk.gov.di.ipv.core.processcandidateidentity;

import com.amazonaws.services.lambda.runtime.Context;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.Spy;
import org.mockito.junit.jupiter.MockitoExtension;
import uk.gov.di.ipv.core.library.auditing.AuditEventUser;
import uk.gov.di.ipv.core.library.cimit.exception.CiRetrievalException;
import uk.gov.di.ipv.core.library.cimit.service.CimitService;
import uk.gov.di.ipv.core.library.cristoringservice.CriStoringService;
import uk.gov.di.ipv.core.library.domain.Cri;
import uk.gov.di.ipv.core.library.domain.JourneyResponse;
import uk.gov.di.ipv.core.library.domain.ProcessRequest;
import uk.gov.di.ipv.core.library.enums.CandidateIdentityType;
import uk.gov.di.ipv.core.library.evcs.exception.EvcsServiceException;
import uk.gov.di.ipv.core.library.exceptions.CiExtractionException;
import uk.gov.di.ipv.core.library.exceptions.CredentialParseException;
import uk.gov.di.ipv.core.library.exceptions.IpvSessionNotFoundException;
import uk.gov.di.ipv.core.library.exceptions.VerifiableCredentialException;
import uk.gov.di.ipv.core.library.persistence.item.ClientOAuthSessionItem;
import uk.gov.di.ipv.core.library.persistence.item.IpvSessionItem;
import uk.gov.di.ipv.core.library.service.AuditService;
import uk.gov.di.ipv.core.library.service.CimitUtilityService;
import uk.gov.di.ipv.core.library.service.ClientOAuthSessionDetailsService;
import uk.gov.di.ipv.core.library.service.ConfigService;
import uk.gov.di.ipv.core.library.service.IpvSessionService;
import uk.gov.di.ipv.core.library.testhelpers.unit.LogCollector;
import uk.gov.di.ipv.core.library.ticf.TicfCriService;
import uk.gov.di.ipv.core.library.useridentity.service.UserIdentityService;
import uk.gov.di.ipv.core.library.useridentity.service.VotMatcher;
import uk.gov.di.ipv.core.library.useridentity.service.VotMatchingResult;
import uk.gov.di.ipv.core.library.verifiablecredential.service.SessionCredentialsService;
import uk.gov.di.ipv.core.processcandidateidentity.service.CheckCoiService;
import uk.gov.di.ipv.core.processcandidateidentity.service.StoreIdentityService;
import uk.gov.di.model.ContraIndicator;

import java.util.List;
import java.util.Map;
import java.util.Optional;

import static com.nimbusds.oauth2.sdk.http.HTTPResponse.SC_SERVER_ERROR;
import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.core.StringContains.containsString;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyBoolean;
import static org.mockito.ArgumentMatchers.anyList;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.doThrow;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;
import static uk.gov.di.ipv.core.library.config.ConfigurationVariable.CREDENTIAL_ISSUER_ENABLED;
import static uk.gov.di.ipv.core.library.domain.ErrorResponse.ERROR_PROCESSING_TICF_CRI_RESPONSE;
import static uk.gov.di.ipv.core.library.domain.ErrorResponse.FAILED_TO_EXTRACT_CIS_FROM_VC;
import static uk.gov.di.ipv.core.library.domain.ErrorResponse.FAILED_TO_GET_CREDENTIAL;
import static uk.gov.di.ipv.core.library.domain.ErrorResponse.FAILED_TO_PARSE_ISSUED_CREDENTIALS;
import static uk.gov.di.ipv.core.library.domain.ErrorResponse.IPV_SESSION_NOT_FOUND;
import static uk.gov.di.ipv.core.library.domain.ErrorResponse.MISSING_PROCESS_IDENTITY_TYPE;
import static uk.gov.di.ipv.core.library.domain.ErrorResponse.MISSING_SECURITY_CHECK_CREDENTIAL;
import static uk.gov.di.ipv.core.library.domain.ErrorResponse.RECEIVED_NON_200_RESPONSE_STATUS_CODE;
import static uk.gov.di.ipv.core.library.domain.ErrorResponse.UNEXPECTED_PROCESS_IDENTITY_TYPE;
import static uk.gov.di.ipv.core.library.enums.CoiCheckType.ACCOUNT_INTERVENTION;
import static uk.gov.di.ipv.core.library.enums.CoiCheckType.REVERIFICATION;
import static uk.gov.di.ipv.core.library.enums.CoiCheckType.STANDARD;
import static uk.gov.di.ipv.core.library.enums.Vot.P2;
import static uk.gov.di.ipv.core.library.fixtures.TestFixtures.SIGNED_CIMIT_VC_NO_CI;
import static uk.gov.di.ipv.core.library.fixtures.VcFixtures.vcTicf;
import static uk.gov.di.ipv.core.library.fixtures.VcFixtures.vcTicfWithCi;
import static uk.gov.di.ipv.core.library.gpg45.enums.Gpg45Profile.M1A;
import static uk.gov.di.ipv.core.library.journeys.JourneyUris.JOURNEY_COI_CHECK_FAILED_PATH;
import static uk.gov.di.ipv.core.library.journeys.JourneyUris.JOURNEY_ERROR_PATH;
import static uk.gov.di.ipv.core.library.journeys.JourneyUris.JOURNEY_FAIL_WITH_CI_PATH;
import static uk.gov.di.ipv.core.library.journeys.JourneyUris.JOURNEY_NEXT_PATH;
import static uk.gov.di.ipv.core.library.journeys.JourneyUris.JOURNEY_PROFILE_UNMET_PATH;
import static uk.gov.di.ipv.core.library.journeys.JourneyUris.JOURNEY_VCS_NOT_CORRELATED;

@ExtendWith(MockitoExtension.class)
class ProcessCandidateIdentityHandlerTest {
    private static ProcessRequest.ProcessRequestBuilder requestBuilder;

    private static final String SESSION_ID = "session-id";
    private static final String IP_ADDRESS = "ip-address";
    private static final String DEVICE_INFORMATION = "device_information";
    private static final String SIGNIN_JOURNEY_ID = "journey-id";
    private static final String USER_ID = "user-id";
    private static final String PROCESS_IDENTITY_TYPE = "identityType";

    private static final JourneyResponse JOURNEY_NEXT = new JourneyResponse(JOURNEY_NEXT_PATH);

    @Spy private IpvSessionItem ipvSessionItem;
    private ClientOAuthSessionItem clientOAuthSessionItem;
    private ClientOAuthSessionItem.ClientOAuthSessionItemBuilder clientOAuthSessionItemBuilder;

    @Mock private Context context;
    @Mock private ConfigService configService;
    @Mock private IpvSessionService ipvSessionService;
    @Mock private ClientOAuthSessionDetailsService clientOAuthSessionDetailsService;
    @Mock private AuditService auditService;
    @Mock private SessionCredentialsService sessionCredentialsService;
    @Mock private CheckCoiService checkCoiService;
    @Mock private VotMatcher votMatcher;
    @Mock private StoreIdentityService storeIdentityService;
    @Mock private UserIdentityService userIdentityService;
    @Mock private TicfCriService ticfCriService;
    @Mock private CriStoringService criStoringService;
    @Mock private CimitUtilityService cimitUtilityService;
    @Mock private CimitService cimitService;
    @InjectMocks ProcessCandidateIdentityHandler processCandidateIdentityHandler;

    @BeforeEach
    void setUp() {
        requestBuilder =
                ProcessRequest.processRequestBuilder()
                        .ipvSessionId(SESSION_ID)
                        .ipAddress(IP_ADDRESS)
                        .deviceInformation(DEVICE_INFORMATION);

        clientOAuthSessionItemBuilder =
                ClientOAuthSessionItem.builder()
                        .userId(USER_ID)
                        .govukSigninJourneyId(SIGNIN_JOURNEY_ID)
                        .vtr(List.of())
                        .reproveIdentity(false);

        ipvSessionItem.setIpvSessionId(SESSION_ID);
        ipvSessionItem.setVot(P2);
        ipvSessionItem.setSecurityCheckCredential(SIGNED_CIMIT_VC_NO_CI);
    }

    @Nested
    class processIdentity {
        @BeforeEach
        void setUp() throws Exception {
            clientOAuthSessionItem =
                    clientOAuthSessionItemBuilder.vtr(List.of("P2")).scope("openid").build();
            when(ipvSessionService.getIpvSession(SESSION_ID)).thenReturn(ipvSessionItem);
            when(clientOAuthSessionDetailsService.getClientOAuthSession(any()))
                    .thenReturn(clientOAuthSessionItem);
        }

        @Test
        void shouldHandleCandidateIdentityTypeNewAndReturnJourneyNext() throws Exception {
            // Arrange
            var ticfVcs = List.of(vcTicf());
            when(checkCoiService.isCoiCheckSuccessful(
                            eq(ipvSessionItem),
                            eq(clientOAuthSessionItem),
                            eq(STANDARD),
                            eq(DEVICE_INFORMATION),
                            eq(List.of()),
                            any(AuditEventUser.class)))
                    .thenReturn(true);
            when(votMatcher.matchFirstVot(anyList(), eq(List.of()), eq(List.of()), eq(true)))
                    .thenReturn(Optional.of(new VotMatchingResult(P2, M1A, M1A.getScores())));
            when(userIdentityService.areVcsCorrelated(List.of())).thenReturn(true);
            when(configService.getBooleanParameter(CREDENTIAL_ISSUER_ENABLED, Cri.TICF.getId()))
                    .thenReturn(true);
            when(ticfCriService.getTicfVc(clientOAuthSessionItem, ipvSessionItem))
                    .thenReturn(ticfVcs);
            when(cimitUtilityService.getContraIndicatorsFromVc(any(), any())).thenReturn(List.of());
            when(cimitUtilityService.getMitigationJourneyIfBreaching(List.of(), P2))
                    .thenReturn(Optional.empty());

            var request =
                    requestBuilder
                            .lambdaInput(
                                    Map.of(PROCESS_IDENTITY_TYPE, CandidateIdentityType.NEW.name()))
                            .build();

            // Act
            var response = processCandidateIdentityHandler.handleRequest(request, context);

            // Assert
            assertEquals(JOURNEY_NEXT.getJourney(), response.get("journey"));

            verify(storeIdentityService, times(1))
                    .storeIdentity(
                            eq(ipvSessionItem),
                            eq(clientOAuthSessionItem),
                            eq(CandidateIdentityType.NEW),
                            eq(DEVICE_INFORMATION),
                            eq(List.of()),
                            any(AuditEventUser.class));
            verify(criStoringService, times(1))
                    .storeVcs(
                            eq(Cri.TICF),
                            eq(IP_ADDRESS),
                            eq(DEVICE_INFORMATION),
                            eq(ticfVcs),
                            eq(clientOAuthSessionItem),
                            eq(ipvSessionItem),
                            eq(List.of()),
                            any(AuditEventUser.class));
        }

        @Test
        void shouldHandleCandidateIdentityTypePendingAndReturnJourneyNext() throws Exception {
            // Arrange
            var ticfVcs = List.of(vcTicf());
            when(checkCoiService.isCoiCheckSuccessful(
                            eq(ipvSessionItem),
                            eq(clientOAuthSessionItem),
                            eq(STANDARD),
                            eq(DEVICE_INFORMATION),
                            eq(List.of()),
                            any(AuditEventUser.class)))
                    .thenReturn(true);
            when(configService.getBooleanParameter(CREDENTIAL_ISSUER_ENABLED, Cri.TICF.getId()))
                    .thenReturn(true);
            when(ticfCriService.getTicfVc(clientOAuthSessionItem, ipvSessionItem))
                    .thenReturn(ticfVcs);
            when(cimitUtilityService.getMitigationJourneyIfBreaching(List.of(), P2))
                    .thenReturn(Optional.empty());
            when(cimitUtilityService.getContraIndicatorsFromVc(any())).thenReturn(List.of());

            var request =
                    requestBuilder
                            .lambdaInput(
                                    Map.of(
                                            PROCESS_IDENTITY_TYPE,
                                            CandidateIdentityType.PENDING.name()))
                            .build();

            // Act
            var response = processCandidateIdentityHandler.handleRequest(request, context);

            // Assert
            assertEquals(JOURNEY_NEXT.getJourney(), response.get("journey"));

            verify(votMatcher, times(0)).matchFirstVot(any(), any(), any(), anyBoolean());
            verify(storeIdentityService, times(1))
                    .storeIdentity(
                            eq(ipvSessionItem),
                            eq(clientOAuthSessionItem),
                            eq(CandidateIdentityType.PENDING),
                            eq(DEVICE_INFORMATION),
                            eq(List.of()),
                            any(AuditEventUser.class));
            verify(criStoringService, times(1))
                    .storeVcs(
                            eq(Cri.TICF),
                            eq(IP_ADDRESS),
                            eq(DEVICE_INFORMATION),
                            eq(ticfVcs),
                            eq(clientOAuthSessionItem),
                            eq(ipvSessionItem),
                            eq(List.of()),
                            any(AuditEventUser.class));
        }

        @Test
        void shouldHandleCandidateIdentityTypePendingAndReturnCimitResponse() throws Exception {
            // Arrange
            var cimitResponse = new JourneyResponse("dummy-response");
            var ticfVcs = List.of(vcTicf());
            when(checkCoiService.isCoiCheckSuccessful(
                            eq(ipvSessionItem),
                            eq(clientOAuthSessionItem),
                            eq(STANDARD),
                            eq(DEVICE_INFORMATION),
                            eq(List.of()),
                            any(AuditEventUser.class)))
                    .thenReturn(true);
            when(configService.getBooleanParameter(CREDENTIAL_ISSUER_ENABLED, Cri.TICF.getId()))
                    .thenReturn(true);
            when(ticfCriService.getTicfVc(clientOAuthSessionItem, ipvSessionItem))
                    .thenReturn(ticfVcs);
            when(cimitUtilityService.getMitigationJourneyIfBreaching(List.of(), P2))
                    .thenReturn(Optional.of(cimitResponse));
            when(cimitUtilityService.getContraIndicatorsFromVc(any()))
                    .thenReturn(List.of())
                    .thenReturn(List.of());

            var request =
                    requestBuilder
                            .lambdaInput(
                                    Map.of(
                                            PROCESS_IDENTITY_TYPE,
                                            CandidateIdentityType.PENDING.name()))
                            .build();

            // Act
            var response = processCandidateIdentityHandler.handleRequest(request, context);

            // Assert
            assertEquals(cimitResponse.getJourney(), response.get("journey"));

            verify(votMatcher, times(0)).matchFirstVot(any(), any(), any(), anyBoolean());
            verify(storeIdentityService, times(1))
                    .storeIdentity(
                            eq(ipvSessionItem),
                            eq(clientOAuthSessionItem),
                            eq(CandidateIdentityType.PENDING),
                            eq(DEVICE_INFORMATION),
                            eq(List.of()),
                            any(AuditEventUser.class));
            verify(criStoringService, times(1))
                    .storeVcs(
                            eq(Cri.TICF),
                            eq(IP_ADDRESS),
                            eq(DEVICE_INFORMATION),
                            eq(ticfVcs),
                            eq(clientOAuthSessionItem),
                            eq(ipvSessionItem),
                            eq(List.of()),
                            any(AuditEventUser.class));
        }

        @Test
        void shouldHandleCandidateIdentityTypeReverificationAndReturnJourneyNext()
                throws Exception {
            // Arrange
            clientOAuthSessionItem.setVtr(null);
            clientOAuthSessionItem.setScope("reverification");

            var ticfVcs = List.of(vcTicf());
            when(checkCoiService.isCoiCheckSuccessful(
                            eq(ipvSessionItem),
                            eq(clientOAuthSessionItem),
                            eq(REVERIFICATION),
                            eq(DEVICE_INFORMATION),
                            eq(List.of()),
                            any(AuditEventUser.class)))
                    .thenReturn(true);
            when(configService.getBooleanParameter(CREDENTIAL_ISSUER_ENABLED, Cri.TICF.getId()))
                    .thenReturn(true);
            when(ticfCriService.getTicfVc(clientOAuthSessionItem, ipvSessionItem))
                    .thenReturn(ticfVcs);

            var request =
                    requestBuilder
                            .lambdaInput(
                                    Map.of(
                                            PROCESS_IDENTITY_TYPE,
                                            CandidateIdentityType.REVERIFICATION.name()))
                            .build();

            // Act
            var response = processCandidateIdentityHandler.handleRequest(request, context);

            // Assert
            assertEquals(JOURNEY_NEXT.getJourney(), response.get("journey"));

            verify(votMatcher, times(0)).matchFirstVot(any(), any(), any(), anyBoolean());
            verify(storeIdentityService, times(0))
                    .storeIdentity(any(), any(), any(), any(), any(), any());
            verify(criStoringService, times(1))
                    .storeVcs(
                            eq(Cri.TICF),
                            eq(IP_ADDRESS),
                            eq(DEVICE_INFORMATION),
                            eq(ticfVcs),
                            eq(clientOAuthSessionItem),
                            eq(ipvSessionItem),
                            eq(List.of()),
                            any(AuditEventUser.class));
        }

        @Test
        void shouldHandleCandidateIdentityTypeExistingAndReturnJourneyNext() throws Exception {
            // Arrange
            var ticfVcs = List.of(vcTicf());
            when(configService.getBooleanParameter(CREDENTIAL_ISSUER_ENABLED, Cri.TICF.getId()))
                    .thenReturn(true);
            when(ticfCriService.getTicfVc(clientOAuthSessionItem, ipvSessionItem))
                    .thenReturn(ticfVcs);
            when(cimitUtilityService.getContraIndicatorsFromVc(any(), any())).thenReturn(List.of());
            when(cimitUtilityService.getMitigationJourneyIfBreaching(List.of(), P2))
                    .thenReturn(Optional.empty());
            when(userIdentityService.areVcsCorrelated(any())).thenReturn(true);
            when(votMatcher.matchFirstVot(List.of(P2), List.of(), List.of(), true))
                    .thenReturn(Optional.of(new VotMatchingResult(P2, M1A, M1A.getScores())));

            var request =
                    requestBuilder
                            .lambdaInput(
                                    Map.of(
                                            PROCESS_IDENTITY_TYPE,
                                            CandidateIdentityType.EXISTING.name()))
                            .build();

            // Act
            var response = processCandidateIdentityHandler.handleRequest(request, context);

            // Assert
            assertEquals(JOURNEY_NEXT.getJourney(), response.get("journey"));

            verify(storeIdentityService, times(0))
                    .storeIdentity(any(), any(), any(), any(), any(), any());
            verify(checkCoiService, times(0))
                    .isCoiCheckSuccessful(any(), any(), any(), any(), any(), any());
        }

        @Test
        void shouldHandleCandidateIdentityTypeIncompleteAndReturnJourneyNext() throws Exception {
            // Arrange
            var ticfVcs = List.of(vcTicf());
            when(configService.getBooleanParameter(CREDENTIAL_ISSUER_ENABLED, Cri.TICF.getId()))
                    .thenReturn(true);
            when(ticfCriService.getTicfVc(clientOAuthSessionItem, ipvSessionItem))
                    .thenReturn(ticfVcs);
            when(cimitUtilityService.getMitigationJourneyIfBreaching(List.of(), P2))
                    .thenReturn(Optional.empty());
            when(cimitUtilityService.getContraIndicatorsFromVc(any())).thenReturn(List.of());

            var request =
                    requestBuilder
                            .lambdaInput(
                                    Map.of(
                                            PROCESS_IDENTITY_TYPE,
                                            CandidateIdentityType.INCOMPLETE.name()))
                            .build();

            // Act
            var response = processCandidateIdentityHandler.handleRequest(request, context);

            // Assert
            assertEquals(JOURNEY_NEXT.getJourney(), response.get("journey"));

            verify(votMatcher, times(0)).matchFirstVot(any(), any(), any(), anyBoolean());
            verify(storeIdentityService, times(0))
                    .storeIdentity(any(), any(), any(), any(), any(), any());
            verify(checkCoiService, times(0))
                    .isCoiCheckSuccessful(any(), any(), any(), any(), any(), any());
        }

        @Test
        void shouldHandleCandidateIdentityTypeUpdateAndReturnJourneyNext() throws Exception {
            // Arrange
            var ticfVcs = List.of(vcTicf());
            when(checkCoiService.isCoiCheckSuccessful(
                            eq(ipvSessionItem),
                            eq(clientOAuthSessionItem),
                            eq(STANDARD),
                            eq(DEVICE_INFORMATION),
                            eq(List.of()),
                            any(AuditEventUser.class)))
                    .thenReturn(true);
            when(votMatcher.matchFirstVot(anyList(), eq(List.of()), eq(List.of()), eq(true)))
                    .thenReturn(Optional.of(new VotMatchingResult(P2, M1A, M1A.getScores())));
            when(userIdentityService.areVcsCorrelated(List.of())).thenReturn(true);
            when(configService.getBooleanParameter(CREDENTIAL_ISSUER_ENABLED, Cri.TICF.getId()))
                    .thenReturn(true);
            when(ticfCriService.getTicfVc(clientOAuthSessionItem, ipvSessionItem))
                    .thenReturn(ticfVcs);
            when(cimitUtilityService.getContraIndicatorsFromVc(any(), any())).thenReturn(List.of());
            when(cimitUtilityService.getMitigationJourneyIfBreaching(List.of(), P2))
                    .thenReturn(Optional.empty());

            var request =
                    requestBuilder
                            .lambdaInput(
                                    Map.of(
                                            PROCESS_IDENTITY_TYPE,
                                            CandidateIdentityType.UPDATE.name()))
                            .build();

            // Act
            var response = processCandidateIdentityHandler.handleRequest(request, context);

            // Assert
            assertEquals(JOURNEY_NEXT.getJourney(), response.get("journey"));

            verify(storeIdentityService, times(1))
                    .storeIdentity(
                            eq(ipvSessionItem),
                            eq(clientOAuthSessionItem),
                            eq(CandidateIdentityType.UPDATE),
                            eq(DEVICE_INFORMATION),
                            eq(List.of()),
                            any(AuditEventUser.class));
            verify(criStoringService, times(1))
                    .storeVcs(
                            eq(Cri.TICF),
                            eq(IP_ADDRESS),
                            eq(DEVICE_INFORMATION),
                            eq(ticfVcs),
                            eq(clientOAuthSessionItem),
                            eq(ipvSessionItem),
                            eq(List.of()),
                            any(AuditEventUser.class));
        }

        @Test
        void shouldNotCallTicfIfDisabled() throws Exception {
            // Arrange
            when(configService.getBooleanParameter(CREDENTIAL_ISSUER_ENABLED, Cri.TICF.getId()))
                    .thenReturn(false);

            var request =
                    requestBuilder
                            .lambdaInput(
                                    Map.of(
                                            PROCESS_IDENTITY_TYPE,
                                            CandidateIdentityType.INCOMPLETE.name()))
                            .build();

            // Act
            var response = processCandidateIdentityHandler.handleRequest(request, context);

            // Assert
            assertEquals(JOURNEY_NEXT.getJourney(), response.get("journey"));

            verify(votMatcher, times(0)).matchFirstVot(any(), any(), any(), anyBoolean());
            verify(storeIdentityService, times(0))
                    .storeIdentity(any(), any(), any(), any(), any(), any());
            verify(checkCoiService, times(0))
                    .isCoiCheckSuccessful(any(), any(), any(), any(), any(), any());
            verify(ticfCriService, times(0)).getTicfVc(any(), any());
        }

        @Test
        void shouldHandleCoiFailure() throws Exception {
            // Arrange
            when(checkCoiService.isCoiCheckSuccessful(
                            eq(ipvSessionItem),
                            eq(clientOAuthSessionItem),
                            eq(STANDARD),
                            eq(DEVICE_INFORMATION),
                            eq(List.of()),
                            any(AuditEventUser.class)))
                    .thenReturn(false);

            var request =
                    requestBuilder
                            .lambdaInput(
                                    Map.of(PROCESS_IDENTITY_TYPE, CandidateIdentityType.NEW.name()))
                            .build();

            // Act
            var response = processCandidateIdentityHandler.handleRequest(request, context);

            // Assert
            assertEquals(JOURNEY_COI_CHECK_FAILED_PATH, response.get("journey"));

            verify(storeIdentityService, times(0))
                    .storeIdentity(any(), any(), any(), any(), anyList(), any());
        }

        @Test
        void shouldHandleCorrelationFailure() throws Exception {
            // Arrange
            when(checkCoiService.isCoiCheckSuccessful(
                            eq(ipvSessionItem),
                            eq(clientOAuthSessionItem),
                            eq(STANDARD),
                            eq(DEVICE_INFORMATION),
                            eq(List.of()),
                            any(AuditEventUser.class)))
                    .thenReturn(true);
            when(userIdentityService.areVcsCorrelated(List.of())).thenReturn(false);

            var request =
                    requestBuilder
                            .lambdaInput(
                                    Map.of(PROCESS_IDENTITY_TYPE, CandidateIdentityType.NEW.name()))
                            .build();

            // Act
            var response = processCandidateIdentityHandler.handleRequest(request, context);

            // Assert
            assertEquals(JOURNEY_VCS_NOT_CORRELATED, response.get("journey"));

            verify(storeIdentityService, times(0))
                    .storeIdentity(any(), any(), any(), any(), anyList(), any());
        }

        @Test
        void shouldHandleNoProfileMatch() throws Exception {
            // Arrange
            when(checkCoiService.isCoiCheckSuccessful(
                            eq(ipvSessionItem),
                            eq(clientOAuthSessionItem),
                            eq(STANDARD),
                            eq(DEVICE_INFORMATION),
                            eq(List.of()),
                            any(AuditEventUser.class)))
                    .thenReturn(true);
            when(votMatcher.matchFirstVot(anyList(), eq(List.of()), eq(List.of()), eq(true)))
                    .thenReturn(Optional.empty());
            when(userIdentityService.areVcsCorrelated(List.of())).thenReturn(true);

            var request =
                    requestBuilder
                            .lambdaInput(
                                    Map.of(PROCESS_IDENTITY_TYPE, CandidateIdentityType.NEW.name()))
                            .build();

            // Act
            var response = processCandidateIdentityHandler.handleRequest(request, context);

            // Assert
            assertEquals(JOURNEY_PROFILE_UNMET_PATH, response.get("journey"));

            verify(storeIdentityService, times(0))
                    .storeIdentity(any(), any(), any(), any(), anyList(), any());
        }

        @Test
        void shouldHandleTicfBreachingContraindicator() throws Exception {
            // Arrange
            var ticfVcs = List.of(vcTicfWithCi());
            var ticfCis = List.of(new ContraIndicator());
            when(checkCoiService.isCoiCheckSuccessful(
                            eq(ipvSessionItem),
                            eq(clientOAuthSessionItem),
                            eq(STANDARD),
                            eq(DEVICE_INFORMATION),
                            eq(List.of()),
                            any(AuditEventUser.class)))
                    .thenReturn(true);
            when(votMatcher.matchFirstVot(anyList(), eq(List.of()), eq(ticfCis), eq(true)))
                    .thenReturn(Optional.of(new VotMatchingResult(P2, M1A, M1A.getScores())));
            when(userIdentityService.areVcsCorrelated(List.of())).thenReturn(true);
            when(configService.getBooleanParameter(CREDENTIAL_ISSUER_ENABLED, Cri.TICF.getId()))
                    .thenReturn(true);
            when(ticfCriService.getTicfVc(clientOAuthSessionItem, ipvSessionItem))
                    .thenReturn(ticfVcs);
            when(cimitUtilityService.getContraIndicatorsFromVc(any(), any())).thenReturn(ticfCis);
            when(cimitUtilityService.getContraIndicatorsFromVc(any())).thenReturn(ticfCis);
            when(cimitUtilityService.getMitigationJourneyIfBreaching(ticfCis, P2))
                    .thenReturn(Optional.of(new JourneyResponse(JOURNEY_FAIL_WITH_CI_PATH)));
            var request =
                    requestBuilder
                            .lambdaInput(
                                    Map.of(PROCESS_IDENTITY_TYPE, CandidateIdentityType.NEW.name()))
                            .build();

            // Act
            var response = processCandidateIdentityHandler.handleRequest(request, context);

            // Assert
            assertEquals(JOURNEY_FAIL_WITH_CI_PATH, response.get("journey"));

            verify(storeIdentityService, times(0))
                    .storeIdentity(any(), any(), any(), any(), anyList(), any());
        }

        @Test
        void shouldHandleReproveIdentityAndReturnJourneyNext() throws Exception {
            // Arrange
            var reproveIdentityClientOAuthSessionItem =
                    clientOAuthSessionItemBuilder.reproveIdentity(true).vtr(List.of("P2")).build();
            when(clientOAuthSessionDetailsService.getClientOAuthSession(any()))
                    .thenReturn(reproveIdentityClientOAuthSessionItem);

            var ticfVcs = List.of(vcTicf());
            when(checkCoiService.isCoiCheckSuccessful(
                            eq(ipvSessionItem),
                            eq(reproveIdentityClientOAuthSessionItem),
                            eq(ACCOUNT_INTERVENTION),
                            eq(DEVICE_INFORMATION),
                            eq(List.of()),
                            any(AuditEventUser.class)))
                    .thenReturn(true);
            when(votMatcher.matchFirstVot(anyList(), eq(List.of()), eq(List.of()), eq(true)))
                    .thenReturn(Optional.of(new VotMatchingResult(P2, M1A, M1A.getScores())));
            when(userIdentityService.areVcsCorrelated(List.of())).thenReturn(true);
            when(configService.getBooleanParameter(CREDENTIAL_ISSUER_ENABLED, Cri.TICF.getId()))
                    .thenReturn(true);
            when(ticfCriService.getTicfVc(reproveIdentityClientOAuthSessionItem, ipvSessionItem))
                    .thenReturn(ticfVcs);
            when(cimitUtilityService.getContraIndicatorsFromVc(any(), any())).thenReturn(List.of());
            when(cimitUtilityService.getMitigationJourneyIfBreaching(List.of(), P2))
                    .thenReturn(Optional.empty());

            var request =
                    requestBuilder
                            .lambdaInput(
                                    Map.of(PROCESS_IDENTITY_TYPE, CandidateIdentityType.NEW.name()))
                            .build();

            // Act
            var response = processCandidateIdentityHandler.handleRequest(request, context);

            // Assert
            assertEquals(JOURNEY_NEXT.getJourney(), response.get("journey"));

            verify(storeIdentityService, times(1))
                    .storeIdentity(
                            eq(ipvSessionItem),
                            eq(reproveIdentityClientOAuthSessionItem),
                            eq(CandidateIdentityType.NEW),
                            eq(DEVICE_INFORMATION),
                            eq(List.of()),
                            any(AuditEventUser.class));
            verify(criStoringService, times(1))
                    .storeVcs(
                            eq(Cri.TICF),
                            eq(IP_ADDRESS),
                            eq(DEVICE_INFORMATION),
                            eq(ticfVcs),
                            eq(reproveIdentityClientOAuthSessionItem),
                            eq(ipvSessionItem),
                            eq(List.of()),
                            any(AuditEventUser.class));
        }

        @Test
        void shouldReturnJourneyErrorForCredentialParseException() throws Exception {
            // Arrange
            when(checkCoiService.isCoiCheckSuccessful(any(), any(), any(), any(), any(), any()))
                    .thenThrow(new CredentialParseException("Unable to parse credentials"));

            var request =
                    requestBuilder
                            .lambdaInput(
                                    Map.of(PROCESS_IDENTITY_TYPE, CandidateIdentityType.NEW.name()))
                            .build();

            // Act
            var response = processCandidateIdentityHandler.handleRequest(request, context);

            // Assert
            assertEquals(JOURNEY_ERROR_PATH, response.get("journey"));
            assertEquals(500, response.get("statusCode"));
            assertEquals(FAILED_TO_PARSE_ISSUED_CREDENTIALS.getMessage(), response.get("message"));

            verify(storeIdentityService, times(0))
                    .storeIdentity(any(), any(), any(), any(), anyList(), any());
        }

        @Test
        void shouldReturnJourneyErrorForFailedCiExtraction() throws Exception {
            // Arrange
            when(checkCoiService.isCoiCheckSuccessful(
                            eq(ipvSessionItem),
                            eq(clientOAuthSessionItem),
                            eq(STANDARD),
                            eq(DEVICE_INFORMATION),
                            eq(List.of()),
                            any(AuditEventUser.class)))
                    .thenReturn(true);
            when(userIdentityService.areVcsCorrelated(List.of())).thenReturn(true);
            when(cimitUtilityService.getContraIndicatorsFromVc(any(), any()))
                    .thenThrow(new CiExtractionException("Could not extract CIs"));

            var request =
                    requestBuilder
                            .lambdaInput(
                                    Map.of(PROCESS_IDENTITY_TYPE, CandidateIdentityType.NEW.name()))
                            .build();

            // Act
            var response = processCandidateIdentityHandler.handleRequest(request, context);

            // Assert
            assertEquals(JOURNEY_ERROR_PATH, response.get("journey"));
            assertEquals(500, response.get("statusCode"));
            assertEquals(FAILED_TO_EXTRACT_CIS_FROM_VC.getMessage(), response.get("message"));

            verify(storeIdentityService, times(0))
                    .storeIdentity(any(), any(), any(), any(), anyList(), any());
        }

        @Test
        void shouldReturnJourneyErrorForMissingSecurityCheckCredential() throws Exception {
            // Arrange
            ipvSessionItem.setSecurityCheckCredential(null);
            when(checkCoiService.isCoiCheckSuccessful(
                            eq(ipvSessionItem),
                            eq(clientOAuthSessionItem),
                            eq(STANDARD),
                            eq(DEVICE_INFORMATION),
                            eq(List.of()),
                            any(AuditEventUser.class)))
                    .thenReturn(true);

            var request =
                    requestBuilder
                            .lambdaInput(
                                    Map.of(PROCESS_IDENTITY_TYPE, CandidateIdentityType.NEW.name()))
                            .build();

            // Act
            var response = processCandidateIdentityHandler.handleRequest(request, context);

            // Assert
            assertEquals(JOURNEY_ERROR_PATH, response.get("journey"));
            assertEquals(500, response.get("statusCode"));
            assertEquals(MISSING_SECURITY_CHECK_CREDENTIAL.getMessage(), response.get("message"));

            verify(storeIdentityService, times(0))
                    .storeIdentity(any(), any(), any(), any(), anyList(), any());
        }

        @Test
        void shouldReturnJourneyErrorForFailedCiRetrieval() throws Exception {
            // Arrange
            var ticfVcs = List.of(vcTicf());
            when(checkCoiService.isCoiCheckSuccessful(
                            eq(ipvSessionItem),
                            eq(clientOAuthSessionItem),
                            eq(STANDARD),
                            eq(DEVICE_INFORMATION),
                            eq(List.of()),
                            any(AuditEventUser.class)))
                    .thenReturn(true);
            when(votMatcher.matchFirstVot(anyList(), eq(List.of()), eq(List.of()), eq(true)))
                    .thenReturn(Optional.of(new VotMatchingResult(P2, M1A, M1A.getScores())));
            when(userIdentityService.areVcsCorrelated(List.of())).thenReturn(true);
            when(configService.getBooleanParameter(CREDENTIAL_ISSUER_ENABLED, Cri.TICF.getId()))
                    .thenReturn(true);
            when(ticfCriService.getTicfVc(clientOAuthSessionItem, ipvSessionItem))
                    .thenReturn(ticfVcs);
            when(cimitUtilityService.getContraIndicatorsFromVc(any(), any())).thenReturn(List.of());
            when(cimitService.fetchContraIndicatorsVc(any(), any(), any(), any()))
                    .thenThrow(new CiRetrievalException("Could not retrieve CIs"));

            var request =
                    requestBuilder
                            .lambdaInput(
                                    Map.of(PROCESS_IDENTITY_TYPE, CandidateIdentityType.NEW.name()))
                            .build();

            // Act
            var response = processCandidateIdentityHandler.handleRequest(request, context);

            // Assert
            assertEquals(JOURNEY_ERROR_PATH, response.get("journey"));
            assertEquals(500, response.get("statusCode"));
            assertEquals(ERROR_PROCESSING_TICF_CRI_RESPONSE.getMessage(), response.get("message"));

            verify(storeIdentityService, times(0))
                    .storeIdentity(any(), any(), any(), any(), anyList(), any());
        }

        @Test
        void shouldReturnJourneyErrorWhenFailingToStoreIdentity() throws Exception {
            // Arrange
            var ticfVcs = List.of(vcTicf());
            when(checkCoiService.isCoiCheckSuccessful(
                            eq(ipvSessionItem),
                            eq(clientOAuthSessionItem),
                            eq(STANDARD),
                            eq(DEVICE_INFORMATION),
                            eq(List.of()),
                            any(AuditEventUser.class)))
                    .thenReturn(true);
            when(votMatcher.matchFirstVot(anyList(), eq(List.of()), eq(List.of()), eq(true)))
                    .thenReturn(Optional.of(new VotMatchingResult(P2, M1A, M1A.getScores())));
            when(userIdentityService.areVcsCorrelated(List.of())).thenReturn(true);
            when(configService.getBooleanParameter(CREDENTIAL_ISSUER_ENABLED, Cri.TICF.getId()))
                    .thenReturn(true);
            when(ticfCriService.getTicfVc(clientOAuthSessionItem, ipvSessionItem))
                    .thenReturn(ticfVcs);
            when(cimitUtilityService.getContraIndicatorsFromVc(any(), any()))
                    .thenReturn(List.of())
                    .thenReturn(List.of());
            when(cimitUtilityService.getMitigationJourneyIfBreaching(List.of(), P2))
                    .thenReturn(Optional.empty());
            doThrow(
                            new EvcsServiceException(
                                    SC_SERVER_ERROR, RECEIVED_NON_200_RESPONSE_STATUS_CODE))
                    .when(storeIdentityService)
                    .storeIdentity(any(), any(), any(), any(), anyList(), any());

            var request =
                    requestBuilder
                            .lambdaInput(
                                    Map.of(PROCESS_IDENTITY_TYPE, CandidateIdentityType.NEW.name()))
                            .build();

            // Act
            var response = processCandidateIdentityHandler.handleRequest(request, context);

            // Assert
            assertEquals(JOURNEY_ERROR_PATH, response.get("journey"));
            assertEquals(500, response.get("statusCode"));
            assertEquals(
                    RECEIVED_NON_200_RESPONSE_STATUS_CODE.getMessage(), response.get("message"));
        }

        @Test
        void shouldReturnJourneyErrorWhenFailingToGetSessionVcs() throws Exception {
            // Arrange
            when(sessionCredentialsService.getCredentials(any(), any()))
                    .thenThrow(new VerifiableCredentialException(500, FAILED_TO_GET_CREDENTIAL));

            var request =
                    requestBuilder
                            .lambdaInput(
                                    Map.of(PROCESS_IDENTITY_TYPE, CandidateIdentityType.NEW.name()))
                            .build();

            // Act
            var response = processCandidateIdentityHandler.handleRequest(request, context);

            // Assert
            assertEquals(JOURNEY_ERROR_PATH, response.get("journey"));
            assertEquals(500, response.get("statusCode"));
            assertEquals(FAILED_TO_GET_CREDENTIAL.getMessage(), response.get("message"));
        }
    }

    @Test
    void shouldReturnJourneyErrorIfIdentityTypeIsNotProvided() {
        // Arrange
        var request = requestBuilder.lambdaInput(Map.of()).build();

        // Act
        var response = processCandidateIdentityHandler.handleRequest(request, context);

        // Assert
        assertEquals(JOURNEY_ERROR_PATH, response.get("journey"));
        assertEquals(400, response.get("statusCode"));
        assertEquals(MISSING_PROCESS_IDENTITY_TYPE.getMessage(), response.get("message"));
    }

    @Test
    void shouldReturnJourneyErrorIfIdentityTypeIsInvalid() {
        // Arrange
        var request =
                requestBuilder.lambdaInput(Map.of(PROCESS_IDENTITY_TYPE, "invalid-type")).build();

        // Act
        var response = processCandidateIdentityHandler.handleRequest(request, context);

        // Assert
        assertEquals(JOURNEY_ERROR_PATH, response.get("journey"));
        assertEquals(400, response.get("statusCode"));
        assertEquals(UNEXPECTED_PROCESS_IDENTITY_TYPE.getMessage(), response.get("message"));
    }

    @Test
    void shouldReturnJourneyErrorIfIpvSessionMissing() throws Exception {
        // Arrange
        when(ipvSessionService.getIpvSession(SESSION_ID))
                .thenThrow(new IpvSessionNotFoundException("Oh no"));
        var request =
                requestBuilder
                        .lambdaInput(
                                Map.of(
                                        PROCESS_IDENTITY_TYPE,
                                        CandidateIdentityType.INCOMPLETE.name()))
                        .build();

        // Act
        var response = processCandidateIdentityHandler.handleRequest(request, context);

        // Assert
        assertEquals(JOURNEY_ERROR_PATH, response.get("journey"));
        assertEquals(500, response.get("statusCode"));
        assertEquals(IPV_SESSION_NOT_FOUND.getMessage(), response.get("message"));
    }

    @Test
    void shouldLogRuntimeExceptionsAndRethrow() throws Exception {
        // Arrange
        when(ipvSessionService.getIpvSession(anyString()))
                .thenThrow(new RuntimeException("Test error"));

        var logCollector = LogCollector.getLogCollectorFor(ProcessCandidateIdentityHandler.class);

        var request =
                requestBuilder
                        .lambdaInput(
                                Map.of(PROCESS_IDENTITY_TYPE, CandidateIdentityType.NEW.name()))
                        .build();

        // Act
        var thrown =
                assertThrows(
                        Exception.class,
                        () -> processCandidateIdentityHandler.handleRequest(request, context),
                        "Expected handleRequest() to throw, but it didn't");

        // Assert
        assertEquals("Test error", thrown.getMessage());
        var logMessage = logCollector.getLogMessages().get(0);
        assertThat(logMessage, containsString("Unhandled lambda exception"));
        assertThat(logMessage, containsString("Test error"));
    }
}
