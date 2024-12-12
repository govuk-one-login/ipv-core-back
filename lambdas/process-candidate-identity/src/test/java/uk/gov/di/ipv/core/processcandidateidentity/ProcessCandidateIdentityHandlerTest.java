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
import uk.gov.di.ipv.core.library.cristoringservice.CriStoringService;
import uk.gov.di.ipv.core.library.domain.Cri;
import uk.gov.di.ipv.core.library.domain.JourneyResponse;
import uk.gov.di.ipv.core.library.domain.ProcessRequest;
import uk.gov.di.ipv.core.library.enums.CandidateIdentityType;
import uk.gov.di.ipv.core.library.enums.IdentityType;
import uk.gov.di.ipv.core.library.enums.Vot;
import uk.gov.di.ipv.core.library.exceptions.IpvSessionNotFoundException;
import uk.gov.di.ipv.core.library.persistence.item.ClientOAuthSessionItem;
import uk.gov.di.ipv.core.library.persistence.item.IpvSessionItem;
import uk.gov.di.ipv.core.library.service.*;
import uk.gov.di.ipv.core.library.testhelpers.unit.LogCollector;
import uk.gov.di.ipv.core.library.verifiablecredential.service.SessionCredentialsService;
import uk.gov.di.ipv.core.processcandidateidentity.service.CheckCoiService;
import uk.gov.di.ipv.core.processcandidateidentity.service.EvaluateGpg45ScoresService;
import uk.gov.di.ipv.core.processcandidateidentity.service.StoreIdentityService;
import uk.gov.di.ipv.core.processcandidateidentity.service.TicfCriService;

import java.util.List;
import java.util.Map;
import java.util.Optional;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.core.StringContains.containsString;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;
import static uk.gov.di.ipv.core.library.config.ConfigurationVariable.CREDENTIAL_ISSUER_ENABLED;
import static uk.gov.di.ipv.core.library.domain.ErrorResponse.INVALID_IDENTITY_TYPE_PARAMETER;
import static uk.gov.di.ipv.core.library.domain.ErrorResponse.IPV_SESSION_NOT_FOUND;
import static uk.gov.di.ipv.core.library.domain.ErrorResponse.MISSING_CHECK_TYPE;
import static uk.gov.di.ipv.core.library.domain.ErrorResponse.MISSING_PROCESS_IDENTITY_TYPE;
import static uk.gov.di.ipv.core.library.domain.ErrorResponse.UNEXPECTED_PROCESS_IDENTITY_TYPE;
import static uk.gov.di.ipv.core.library.domain.ErrorResponse.UNKNOWN_CHECK_TYPE;
import static uk.gov.di.ipv.core.library.enums.CoiCheckType.GIVEN_OR_FAMILY_NAME_AND_DOB;
import static uk.gov.di.ipv.core.library.fixtures.VcFixtures.vcTicf;
import static uk.gov.di.ipv.core.library.gpg45.enums.Gpg45Profile.M1A;
import static uk.gov.di.ipv.core.library.journeys.JourneyUris.JOURNEY_ERROR_PATH;
import static uk.gov.di.ipv.core.library.journeys.JourneyUris.JOURNEY_NEXT_PATH;

@ExtendWith(MockitoExtension.class)
public class ProcessCandidateIdentityHandlerTest {
    private static ProcessRequest.ProcessRequestBuilder requestBuilder;

    private static final String SESSION_ID = "session-id";
    private static final String IP_ADDRESS = "ip-address";
    private static final String DEVICE_INFORMATION = "device_information";
    private static final String SIGNIN_JOURNEY_ID = "journey-id";
    private static final String USER_ID = "user-id";

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
    @Mock private EvaluateGpg45ScoresService evaluateGpg45ScoresService;
    @Mock private StoreIdentityService storeIdentityService;
    @Mock private UserIdentityService userIdentityService;
    @Mock private TicfCriService ticfCriService;
    @Mock private CriStoringService criStoringService;
    @Mock private CimitUtilityService cimitUtilityService;
    @Mock private CimitService cimitService;
    @InjectMocks ProcessCandidateIdentityHandler processCandidateIdentityHandler;

    @BeforeEach
    void setUp() throws Exception {
        requestBuilder =
                ProcessRequest.processRequestBuilder()
                        .ipvSessionId(SESSION_ID)
                        .ipAddress(IP_ADDRESS)
                        .deviceInformation(DEVICE_INFORMATION);

        clientOAuthSessionItemBuilder =
                ClientOAuthSessionItem.builder()
                        .userId(USER_ID)
                        .govukSigninJourneyId(SIGNIN_JOURNEY_ID);

        ipvSessionItem.setIpvSessionId(SESSION_ID);
        ipvSessionItem.setVot(Vot.P2);
    }

    @Nested
    class processIdentity {
        @BeforeEach
        void setUp() throws Exception {
            clientOAuthSessionItem = clientOAuthSessionItemBuilder.vtr(List.of("P2")).build();
            when(ipvSessionService.getIpvSession(SESSION_ID)).thenReturn(ipvSessionItem);
            when(clientOAuthSessionDetailsService.getClientOAuthSession(any()))
                    .thenReturn(clientOAuthSessionItem);
        }

        @Test
        void shouldHandleCandidateIdentityTypeNewAndReturnJourneyNext() throws Exception {
            // Arrange
            var ticfVcs = List.of(vcTicf());
            when(checkCoiService.isCoiCheckSuccessful(
                            ipvSessionItem,
                            clientOAuthSessionItem,
                            GIVEN_OR_FAMILY_NAME_AND_DOB,
                            DEVICE_INFORMATION,
                            IP_ADDRESS,
                            List.of()))
                    .thenReturn(true);
            when(evaluateGpg45ScoresService.findMatchingGpg45Profile(
                            List.of(),
                            ipvSessionItem,
                            clientOAuthSessionItem,
                            IP_ADDRESS,
                            DEVICE_INFORMATION,
                            null))
                    .thenReturn(Optional.of(M1A));
            when(userIdentityService.areVcsCorrelated(List.of())).thenReturn(true);
            when(configService.getBooleanParameter(CREDENTIAL_ISSUER_ENABLED, Cri.TICF.getId()))
                    .thenReturn(true);
            when(ticfCriService.getTicfVc(clientOAuthSessionItem, ipvSessionItem))
                    .thenReturn(ticfVcs);
            when(cimitService.getContraIndicators(USER_ID, SIGNIN_JOURNEY_ID, IP_ADDRESS))
                    .thenReturn(List.of());
            when(cimitUtilityService.getMitigationJourneyIfBreaching(
                            List.of(), ipvSessionItem.getThresholdVot()))
                    .thenReturn(Optional.empty());

            var request =
                    requestBuilder
                            .lambdaInput(
                                    Map.of(
                                            "processIdentityType",
                                            CandidateIdentityType.NEW.name(),
                                            "checkType",
                                            GIVEN_OR_FAMILY_NAME_AND_DOB.name(),
                                            "identityType",
                                            IdentityType.NEW.name()))
                            .build();

            // Act
            var response = processCandidateIdentityHandler.handleRequest(request, context);

            // Assert
            assertEquals(JOURNEY_NEXT.getJourney(), response.get("journey"));

            verify(storeIdentityService, times(1))
                    .storeIdentity(
                            ipvSessionItem,
                            clientOAuthSessionItem,
                            IdentityType.NEW,
                            DEVICE_INFORMATION,
                            IP_ADDRESS,
                            List.of());
            verify(criStoringService, times(1))
                    .storeVcs(
                            Cri.TICF,
                            IP_ADDRESS,
                            DEVICE_INFORMATION,
                            ticfVcs,
                            clientOAuthSessionItem,
                            ipvSessionItem,
                            List.of());
            verify(ipvSessionService).updateIpvSession(ipvSessionItem);
        }

        @Test
        void shouldReturnJourneyErrorIfCoiCheckTypeIsNotProvided() {
            // Arrange
            var request =
                    requestBuilder
                            .lambdaInput(
                                    Map.of(
                                            "processIdentityType",
                                            CandidateIdentityType.NEW.name(),
                                            "identityType",
                                            IdentityType.NEW.name()))
                            .build();

            // Act
            var response = processCandidateIdentityHandler.handleRequest(request, context);

            // Assert
            assertEquals(JOURNEY_ERROR_PATH, response.get("journey"));
            assertEquals(400, response.get("statusCode"));
            assertEquals(MISSING_CHECK_TYPE.getMessage(), response.get("message"));
        }

        @Test
        void shouldReturnJourneyErrorIfCoiCheckTypeIsInvalid() throws Exception {
            // Arrange
            var request =
                    requestBuilder
                            .lambdaInput(
                                    Map.of(
                                            "processIdentityType",
                                            CandidateIdentityType.NEW.name(),
                                            "checkType",
                                            "invalid-check-coi-type"))
                            .build();

            // Act
            var response = processCandidateIdentityHandler.handleRequest(request, context);

            // Assert
            assertEquals(JOURNEY_ERROR_PATH, response.get("journey"));
            assertEquals(500, response.get("statusCode"));
            assertEquals(UNKNOWN_CHECK_TYPE.getMessage(), response.get("message"));
        }

        @Test
        void shouldReturnJourneyErrorIfIdentityTypeIsInvalid() throws Exception {
            // Arrange
            var request =
                    requestBuilder
                            .lambdaInput(
                                    Map.of(
                                            "processIdentityType",
                                            CandidateIdentityType.NEW.name(),
                                            "checkType",
                                            GIVEN_OR_FAMILY_NAME_AND_DOB.name(),
                                            "identityType",
                                            "invalid-identity-type"))
                            .build();
            when(checkCoiService.isCoiCheckSuccessful(
                            ipvSessionItem,
                            clientOAuthSessionItem,
                            GIVEN_OR_FAMILY_NAME_AND_DOB,
                            DEVICE_INFORMATION,
                            IP_ADDRESS,
                            List.of()))
                    .thenReturn(true);

            // Act
            var response = processCandidateIdentityHandler.handleRequest(request, context);

            // Assert
            assertEquals(JOURNEY_ERROR_PATH, response.get("journey"));
            assertEquals(400, response.get("statusCode"));
            assertEquals(INVALID_IDENTITY_TYPE_PARAMETER.getMessage(), response.get("message"));
        }

        @Test
        void shouldReturnJourneyErrorIfIdentityTypeIsMissing() throws Exception {
            // Arrange
            var request =
                    requestBuilder
                            .lambdaInput(
                                    Map.of(
                                            "processIdentityType",
                                            CandidateIdentityType.NEW.name(),
                                            "checkType",
                                            GIVEN_OR_FAMILY_NAME_AND_DOB.name()))
                            .build();
            when(checkCoiService.isCoiCheckSuccessful(
                            ipvSessionItem,
                            clientOAuthSessionItem,
                            GIVEN_OR_FAMILY_NAME_AND_DOB,
                            DEVICE_INFORMATION,
                            IP_ADDRESS,
                            List.of()))
                    .thenReturn(true);

            // Act
            var response = processCandidateIdentityHandler.handleRequest(request, context);

            // Assert
            assertEquals(JOURNEY_ERROR_PATH, response.get("journey"));
            assertEquals(400, response.get("statusCode"));
            assertEquals(INVALID_IDENTITY_TYPE_PARAMETER.getMessage(), response.get("message"));
        }

        @Test
        void shouldHandleCandidateIdentityTypePendingAndReturnJourneyNext() throws Exception {
            // Arrange
            var ticfVcs = List.of(vcTicf());
            when(checkCoiService.isCoiCheckSuccessful(
                            ipvSessionItem,
                            clientOAuthSessionItem,
                            GIVEN_OR_FAMILY_NAME_AND_DOB,
                            DEVICE_INFORMATION,
                            IP_ADDRESS,
                            List.of()))
                    .thenReturn(true);
            when(configService.getBooleanParameter(CREDENTIAL_ISSUER_ENABLED, Cri.TICF.getId()))
                    .thenReturn(true);
            when(ticfCriService.getTicfVc(clientOAuthSessionItem, ipvSessionItem))
                    .thenReturn(ticfVcs);
            when(cimitService.getContraIndicators(USER_ID, SIGNIN_JOURNEY_ID, IP_ADDRESS))
                    .thenReturn(List.of());
            when(cimitUtilityService.getMitigationJourneyIfBreaching(
                            List.of(), ipvSessionItem.getThresholdVot()))
                    .thenReturn(Optional.empty());

            var request =
                    requestBuilder
                            .lambdaInput(
                                    Map.of(
                                            "processIdentityType",
                                            CandidateIdentityType.PENDING.name(),
                                            "checkType",
                                            GIVEN_OR_FAMILY_NAME_AND_DOB.name(),
                                            "identityType",
                                            IdentityType.NEW.name()))
                            .build();

            // Act
            var response = processCandidateIdentityHandler.handleRequest(request, context);

            // Assert
            assertEquals(JOURNEY_NEXT.getJourney(), response.get("journey"));

            verify(evaluateGpg45ScoresService, times(0))
                    .findMatchingGpg45Profile(any(), any(), any(), any(), any(), any());
            verify(storeIdentityService, times(1))
                    .storeIdentity(
                            ipvSessionItem,
                            clientOAuthSessionItem,
                            IdentityType.NEW,
                            DEVICE_INFORMATION,
                            IP_ADDRESS,
                            List.of());
            verify(criStoringService, times(1))
                    .storeVcs(
                            Cri.TICF,
                            IP_ADDRESS,
                            DEVICE_INFORMATION,
                            ticfVcs,
                            clientOAuthSessionItem,
                            ipvSessionItem,
                            List.of());
            verify(ipvSessionService).updateIpvSession(ipvSessionItem);
        }

        @Test
        void shouldHandleCandidateIdentityTypeReverificationAndReturnJourneyNext()
                throws Exception {
            // Arrange
            var ticfVcs = List.of(vcTicf());
            when(checkCoiService.isCoiCheckSuccessful(
                            ipvSessionItem,
                            clientOAuthSessionItem,
                            GIVEN_OR_FAMILY_NAME_AND_DOB,
                            DEVICE_INFORMATION,
                            IP_ADDRESS,
                            List.of()))
                    .thenReturn(true);
            when(configService.getBooleanParameter(CREDENTIAL_ISSUER_ENABLED, Cri.TICF.getId()))
                    .thenReturn(true);
            when(ticfCriService.getTicfVc(clientOAuthSessionItem, ipvSessionItem))
                    .thenReturn(ticfVcs);
            when(cimitService.getContraIndicators(USER_ID, SIGNIN_JOURNEY_ID, IP_ADDRESS))
                    .thenReturn(List.of());
            when(cimitUtilityService.getMitigationJourneyIfBreaching(
                            List.of(), ipvSessionItem.getThresholdVot()))
                    .thenReturn(Optional.empty());

            var request =
                    requestBuilder
                            .lambdaInput(
                                    Map.of(
                                            "processIdentityType",
                                            CandidateIdentityType.REVERIFICATION.name(),
                                            "checkType",
                                            GIVEN_OR_FAMILY_NAME_AND_DOB.name()))
                            .build();

            // Act
            var response = processCandidateIdentityHandler.handleRequest(request, context);

            // Assert
            assertEquals(JOURNEY_NEXT.getJourney(), response.get("journey"));

            verify(evaluateGpg45ScoresService, times(0))
                    .findMatchingGpg45Profile(any(), any(), any(), any(), any(), any());
            verify(storeIdentityService, times(0))
                    .storeIdentity(any(), any(), any(), any(), any(), any());
            verify(criStoringService, times(1))
                    .storeVcs(
                            Cri.TICF,
                            IP_ADDRESS,
                            DEVICE_INFORMATION,
                            ticfVcs,
                            clientOAuthSessionItem,
                            ipvSessionItem,
                            List.of());
            verify(ipvSessionService).updateIpvSession(ipvSessionItem);
        }

        @Test
        void shouldHandleCandidateIdentityTypeExistingAndReturnJourneyNext() throws Exception {
            // Arrange
            var ticfVcs = List.of(vcTicf());
            when(configService.getBooleanParameter(CREDENTIAL_ISSUER_ENABLED, Cri.TICF.getId()))
                    .thenReturn(true);
            when(ticfCriService.getTicfVc(clientOAuthSessionItem, ipvSessionItem))
                    .thenReturn(ticfVcs);
            when(cimitService.getContraIndicators(USER_ID, SIGNIN_JOURNEY_ID, IP_ADDRESS))
                    .thenReturn(List.of());
            when(cimitUtilityService.getMitigationJourneyIfBreaching(
                            List.of(), ipvSessionItem.getThresholdVot()))
                    .thenReturn(Optional.empty());

            var request =
                    requestBuilder
                            .lambdaInput(
                                    Map.of(
                                            "processIdentityType",
                                            CandidateIdentityType.EXISTING.name()))
                            .build();

            // Act
            var response = processCandidateIdentityHandler.handleRequest(request, context);

            // Assert
            assertEquals(JOURNEY_NEXT.getJourney(), response.get("journey"));

            verify(evaluateGpg45ScoresService, times(0))
                    .findMatchingGpg45Profile(any(), any(), any(), any(), any(), any());
            verify(storeIdentityService, times(0))
                    .storeIdentity(any(), any(), any(), any(), any(), any());
            verify(checkCoiService, times(0))
                    .isCoiCheckSuccessful(any(), any(), any(), any(), any(), any());
            verify(ipvSessionService).updateIpvSession(ipvSessionItem);
        }

        @Test
        void shouldHandleCandidateIdentityTypeIncompleteAndReturnJourneyNext() throws Exception {
            // Arrange
            var ticfVcs = List.of(vcTicf());
            when(configService.getBooleanParameter(CREDENTIAL_ISSUER_ENABLED, Cri.TICF.getId()))
                    .thenReturn(true);
            when(ticfCriService.getTicfVc(clientOAuthSessionItem, ipvSessionItem))
                    .thenReturn(ticfVcs);
            when(cimitService.getContraIndicators(USER_ID, SIGNIN_JOURNEY_ID, IP_ADDRESS))
                    .thenReturn(List.of());
            when(cimitUtilityService.getMitigationJourneyIfBreaching(
                            List.of(), ipvSessionItem.getThresholdVot()))
                    .thenReturn(Optional.empty());

            var request =
                    requestBuilder
                            .lambdaInput(
                                    Map.of(
                                            "processIdentityType",
                                            CandidateIdentityType.INCOMPLETE.name()))
                            .build();

            // Act
            var response = processCandidateIdentityHandler.handleRequest(request, context);

            // Assert
            assertEquals(JOURNEY_NEXT.getJourney(), response.get("journey"));

            verify(evaluateGpg45ScoresService, times(0))
                    .findMatchingGpg45Profile(any(), any(), any(), any(), any(), any());
            verify(storeIdentityService, times(0))
                    .storeIdentity(any(), any(), any(), any(), any(), any());
            verify(checkCoiService, times(0))
                    .isCoiCheckSuccessful(any(), any(), any(), any(), any(), any());
            verify(ipvSessionService).updateIpvSession(ipvSessionItem);
        }

        @Test
        void shouldNotCallTicfIfDisabled() throws Exception {
            // Arrange
            var ticfVcs = List.of(vcTicf());
            when(configService.getBooleanParameter(CREDENTIAL_ISSUER_ENABLED, Cri.TICF.getId()))
                    .thenReturn(false);

            var request =
                    requestBuilder
                            .lambdaInput(
                                    Map.of(
                                            "processIdentityType",
                                            CandidateIdentityType.INCOMPLETE.name()))
                            .build();

            // Act
            var response = processCandidateIdentityHandler.handleRequest(request, context);

            // Assert
            assertEquals(JOURNEY_NEXT.getJourney(), response.get("journey"));

            verify(evaluateGpg45ScoresService, times(0))
                    .findMatchingGpg45Profile(any(), any(), any(), any(), any(), any());
            verify(storeIdentityService, times(0))
                    .storeIdentity(any(), any(), any(), any(), any(), any());
            verify(checkCoiService, times(0))
                    .isCoiCheckSuccessful(any(), any(), any(), any(), any(), any());
            verify(ticfCriService, times(0)).getTicfVc(any(), any());
            verify(ipvSessionService).updateIpvSession(ipvSessionItem);
        }
    }

    @Test
    void shouldReturnJourneyErrorIfIdentityTypeIsNotProvided() {
        // Arrange
        var request =
                requestBuilder
                        .lambdaInput(Map.of("checkType", GIVEN_OR_FAMILY_NAME_AND_DOB.name()))
                        .build();

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
                requestBuilder.lambdaInput(Map.of("processIdentityType", "invalid-type")).build();

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
                                        "processIdentityType",
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
                                Map.of(
                                        "processIdentityType",
                                        CandidateIdentityType.NEW.name(),
                                        "checkType",
                                        GIVEN_OR_FAMILY_NAME_AND_DOB.name(),
                                        "identityType",
                                        IdentityType.NEW.name()))
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
