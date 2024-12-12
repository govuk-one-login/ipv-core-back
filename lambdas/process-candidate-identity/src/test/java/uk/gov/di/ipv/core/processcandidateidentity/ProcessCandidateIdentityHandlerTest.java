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
import uk.gov.di.ipv.core.library.domain.Cri;
import uk.gov.di.ipv.core.library.domain.JourneyResponse;
import uk.gov.di.ipv.core.library.domain.ProcessRequest;
import uk.gov.di.ipv.core.library.enums.CoiCheckType;
import uk.gov.di.ipv.core.library.enums.IdentityType;
import uk.gov.di.ipv.core.library.enums.ProcessIdentityType;
import uk.gov.di.ipv.core.library.exceptions.IpvSessionNotFoundException;
import uk.gov.di.ipv.core.library.persistence.item.ClientOAuthSessionItem;
import uk.gov.di.ipv.core.library.persistence.item.IpvSessionItem;
import uk.gov.di.ipv.core.library.service.ClientOAuthSessionDetailsService;
import uk.gov.di.ipv.core.library.service.ConfigService;
import uk.gov.di.ipv.core.library.service.IpvSessionService;
import uk.gov.di.ipv.core.library.testhelpers.unit.LogCollector;

import java.util.Map;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.core.StringContains.containsString;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;
import static uk.gov.di.ipv.core.library.config.ConfigurationVariable.CREDENTIAL_ISSUER_ENABLED;
import static uk.gov.di.ipv.core.library.domain.ErrorResponse.INVALID_IDENTITY_TYPE_PARAMETER;
import static uk.gov.di.ipv.core.library.domain.ErrorResponse.IPV_SESSION_NOT_FOUND;
import static uk.gov.di.ipv.core.library.domain.ErrorResponse.MISSING_CHECK_TYPE;
import static uk.gov.di.ipv.core.library.domain.ErrorResponse.MISSING_PROCESS_IDENTITY_TYPE;
import static uk.gov.di.ipv.core.library.domain.ErrorResponse.UNKNOWN_CHECK_TYPE;
import static uk.gov.di.ipv.core.library.enums.CoiCheckType.GIVEN_OR_FAMILY_NAME_AND_DOB;
import static uk.gov.di.ipv.core.library.journeys.JourneyUris.JOURNEY_ERROR_PATH;
import static uk.gov.di.ipv.core.library.journeys.JourneyUris.JOURNEY_NEXT_PATH;

@ExtendWith(MockitoExtension.class)
public class ProcessCandidateIdentityHandlerTest {
    private static ProcessRequest.ProcessRequestBuilder requestBuilder;

    private static final String SESSION_ID = "session-id";
    private static final String IP_ADDRESS = "ip-address";
    private static final String DEVICE_INFORMATION = "device_information";
    private static final String SIGNIN_JOURNEY_ID = "journey-id";

    private static final JourneyResponse JOURNEY_NEXT = new JourneyResponse(JOURNEY_NEXT_PATH);

    @Spy private IpvSessionItem ipvSessionItem;
    private ClientOAuthSessionItem clientOAuthSessionItem;

    @Mock private Context context;
    @Mock private ConfigService configService;
    @Mock private IpvSessionService ipvSessionService;
    @Mock private IdentityProcessingService identityProcessingService;
    @Mock private ClientOAuthSessionDetailsService clientOAuthSessionDetailsService;
    @InjectMocks ProcessCandidateIdentityHandler processCandidateIdentityHandler;

    @BeforeEach
    void setUp() throws Exception {
        requestBuilder =
                ProcessRequest.processRequestBuilder()
                        .ipvSessionId(SESSION_ID)
                        .ipAddress(IP_ADDRESS)
                        .deviceInformation(DEVICE_INFORMATION);

        clientOAuthSessionItem =
                ClientOAuthSessionItem.builder().govukSigninJourneyId(SIGNIN_JOURNEY_ID).build();
    }

    @Nested
    class processIdentityTypeAll {
        @BeforeEach
        void setUp() throws Exception {
            when(ipvSessionService.getIpvSession(SESSION_ID)).thenReturn(ipvSessionItem);
            when(clientOAuthSessionDetailsService.getClientOAuthSession(any()))
                    .thenReturn(clientOAuthSessionItem);
        }

        @Test
        void shouldHandleAllProcessIdentityTypeAndReturnJourneyNext() {
            // Arrange
            var request =
                    requestBuilder
                            .lambdaInput(
                                    Map.of(
                                            "processIdentityType",
                                            ProcessIdentityType.ALL.name(),
                                            "checkType",
                                            GIVEN_OR_FAMILY_NAME_AND_DOB.name(),
                                            "identityType",
                                            IdentityType.NEW.name()))
                            .build();

            when(identityProcessingService.getJourneyResponseFromCoiCheck(
                            ipvSessionItem,
                            clientOAuthSessionItem,
                            GIVEN_OR_FAMILY_NAME_AND_DOB,
                            DEVICE_INFORMATION,
                            IP_ADDRESS))
                    .thenReturn(JOURNEY_NEXT);
            when(identityProcessingService.getJourneyResponseFromGpg45ScoreEvaluation(
                            ipvSessionItem, clientOAuthSessionItem, DEVICE_INFORMATION, IP_ADDRESS))
                    .thenReturn(JOURNEY_NEXT);
            when(identityProcessingService.getJourneyResponseFromTicfCall(
                            ipvSessionItem, clientOAuthSessionItem, DEVICE_INFORMATION, IP_ADDRESS))
                    .thenReturn(JOURNEY_NEXT);
            when(identityProcessingService.getJourneyResponseFromStoringIdentity(
                            ipvSessionItem,
                            clientOAuthSessionItem,
                            IdentityType.NEW,
                            DEVICE_INFORMATION,
                            IP_ADDRESS))
                    .thenReturn(JOURNEY_NEXT);

            // Act
            var response = processCandidateIdentityHandler.handleRequest(request, context);

            // Assert
            assertEquals(JOURNEY_NEXT.getJourney(), response.get("journey"));
            verify(ipvSessionService).updateIpvSession(ipvSessionItem);
        }

        @Test
        void shouldReturnJourneyErrorIfCoiCheckTypeIsNotProvided() throws Exception {
            // Arrange
            var request =
                    requestBuilder
                            .lambdaInput(
                                    Map.of(
                                            "processIdentityType",
                                            ProcessIdentityType.ALL.name(),
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
                                            ProcessIdentityType.ALL.name(),
                                            "checkType",
                                            "invalid-check-coi-type",
                                            "identityType",
                                            IdentityType.NEW.name()))
                            .build();

            // Act
            var response = processCandidateIdentityHandler.handleRequest(request, context);

            // Assert
            assertEquals(JOURNEY_ERROR_PATH, response.get("journey"));
            assertEquals(500, response.get("statusCode"));
            assertEquals(UNKNOWN_CHECK_TYPE.getMessage(), response.get("message"));
        }

        @Test
        void shouldReturnJourneyErrorIfIdentityTypeIsNotProvided() throws Exception {
            // Arrange
            var request =
                    requestBuilder
                            .lambdaInput(
                                    Map.of(
                                            "processIdentityType",
                                            ProcessIdentityType.ALL.name(),
                                            "checkType",
                                            GIVEN_OR_FAMILY_NAME_AND_DOB.name()))
                            .build();

            // Act
            var response = processCandidateIdentityHandler.handleRequest(request, context);

            // Assert
            assertEquals(JOURNEY_ERROR_PATH, response.get("journey"));
            assertEquals(400, response.get("statusCode"));
            assertEquals(INVALID_IDENTITY_TYPE_PARAMETER.getMessage(), response.get("message"));
        }

        @Test
        void shouldReturnJourneyErrorIfIdentityTypeIsInvalid() throws Exception {
            // Arrange
            var request =
                    requestBuilder
                            .lambdaInput(
                                    Map.of(
                                            "processIdentityType",
                                            ProcessIdentityType.ALL.name(),
                                            "checkType",
                                            GIVEN_OR_FAMILY_NAME_AND_DOB.name(),
                                            "identityType",
                                            "invalid-identity-type"))
                            .build();

            // Act
            var response = processCandidateIdentityHandler.handleRequest(request, context);

            // Assert
            assertEquals(JOURNEY_ERROR_PATH, response.get("journey"));
            assertEquals(400, response.get("statusCode"));
            assertEquals(INVALID_IDENTITY_TYPE_PARAMETER.getMessage(), response.get("message"));
        }
    }

    @Nested
    class processIdentityTypeCoi {
        @BeforeEach
        void setUp() throws Exception {
            when(ipvSessionService.getIpvSession(SESSION_ID)).thenReturn(ipvSessionItem);
            when(clientOAuthSessionDetailsService.getClientOAuthSession(any()))
                    .thenReturn(clientOAuthSessionItem);
        }

        @Test
        void shouldHandleCoiProcessIdentityTypeAndReturnJourneyNextWhenTicfIsEnabled()
                throws Exception {
            // Arrange
            var request =
                    requestBuilder
                            .lambdaInput(
                                    Map.of(
                                            "processIdentityType",
                                            ProcessIdentityType.COI.name(),
                                            "checkType",
                                            GIVEN_OR_FAMILY_NAME_AND_DOB.name()))
                            .build();
            when(configService.getBooleanParameter(CREDENTIAL_ISSUER_ENABLED, Cri.TICF.getId()))
                    .thenReturn(true);

            when(identityProcessingService.getJourneyResponseFromCoiCheck(
                            ipvSessionItem,
                            clientOAuthSessionItem,
                            GIVEN_OR_FAMILY_NAME_AND_DOB,
                            DEVICE_INFORMATION,
                            IP_ADDRESS))
                    .thenReturn(JOURNEY_NEXT);
            when(identityProcessingService.getJourneyResponseFromTicfCall(
                            ipvSessionItem, clientOAuthSessionItem, DEVICE_INFORMATION, IP_ADDRESS))
                    .thenReturn(JOURNEY_NEXT);

            // Act
            var response = processCandidateIdentityHandler.handleRequest(request, context);

            // Assert
            assertEquals(JOURNEY_NEXT.getJourney(), response.get("journey"));
            verify(ipvSessionService).updateIpvSession(ipvSessionItem);
        }

        @Test
        void shouldHandleCoiProcessIdentityTypeAndReturnJourneyNextWhenTicfIsDisabled()
                throws Exception {
            // Arrange
            var request =
                    requestBuilder
                            .lambdaInput(
                                    Map.of(
                                            "processIdentityType",
                                            ProcessIdentityType.COI.name(),
                                            "checkType",
                                            GIVEN_OR_FAMILY_NAME_AND_DOB.name()))
                            .build();
            when(configService.getBooleanParameter(CREDENTIAL_ISSUER_ENABLED, Cri.TICF.getId()))
                    .thenReturn(false);

            when(identityProcessingService.getJourneyResponseFromCoiCheck(
                            ipvSessionItem,
                            clientOAuthSessionItem,
                            GIVEN_OR_FAMILY_NAME_AND_DOB,
                            DEVICE_INFORMATION,
                            IP_ADDRESS))
                    .thenReturn(JOURNEY_NEXT);

            // Act
            var response = processCandidateIdentityHandler.handleRequest(request, context);

            // Assert
            assertEquals(JOURNEY_NEXT.getJourney(), response.get("journey"));
            verify(ipvSessionService).updateIpvSession(ipvSessionItem);
        }

        @Test
        void shouldReturnJourneyErrorIfCoiCheckTypeIsInvalid() throws Exception {
            // Arrange
            var request =
                    requestBuilder
                            .lambdaInput(
                                    Map.of(
                                            "processIdentityType",
                                            ProcessIdentityType.COI.name(),
                                            "checkType",
                                            "invalid-check-type"))
                            .build();

            // Act
            var response = processCandidateIdentityHandler.handleRequest(request, context);

            // Assert
            assertEquals(JOURNEY_ERROR_PATH, response.get("journey"));
            assertEquals(500, response.get("statusCode"));
            assertEquals(UNKNOWN_CHECK_TYPE.getMessage(), response.get("message"));
        }

        @Test
        void shouldReturnJourneyErrorIfCoiCheckTypeIsNotProvided() throws Exception {
            // Arrange
            var request =
                    requestBuilder
                            .lambdaInput(
                                    Map.of("processIdentityType", ProcessIdentityType.COI.name()))
                            .build();

            // Act
            var response = processCandidateIdentityHandler.handleRequest(request, context);

            // Assert
            assertEquals(JOURNEY_ERROR_PATH, response.get("journey"));
            assertEquals(400, response.get("statusCode"));
            assertEquals(MISSING_CHECK_TYPE.getMessage(), response.get("message"));
        }
    }

    @Nested
    class processIdentityTypeStoreIdentity {
        @BeforeEach
        void setUp() throws Exception {
            when(ipvSessionService.getIpvSession(SESSION_ID)).thenReturn(ipvSessionItem);
            when(clientOAuthSessionDetailsService.getClientOAuthSession(any()))
                    .thenReturn(clientOAuthSessionItem);
        }

        @Test
        void shouldHandleStoreIdentityProcessIdentityTypeAndReturnJourneyNextWhenTicfIsEnabled()
                throws Exception {
            // Arrange
            var request =
                    requestBuilder
                            .lambdaInput(
                                    Map.of(
                                            "processIdentityType",
                                            ProcessIdentityType.STORE_IDENTITY.name(),
                                            "identityType",
                                            IdentityType.NEW.name()))
                            .build();
            when(configService.getBooleanParameter(CREDENTIAL_ISSUER_ENABLED, Cri.TICF.getId()))
                    .thenReturn(true);

            when(identityProcessingService.getJourneyResponseFromStoringIdentity(
                            ipvSessionItem,
                            clientOAuthSessionItem,
                            IdentityType.NEW,
                            DEVICE_INFORMATION,
                            IP_ADDRESS))
                    .thenReturn(JOURNEY_NEXT);
            when(identityProcessingService.getJourneyResponseFromTicfCall(
                            ipvSessionItem, clientOAuthSessionItem, DEVICE_INFORMATION, IP_ADDRESS))
                    .thenReturn(JOURNEY_NEXT);

            // Act
            var response = processCandidateIdentityHandler.handleRequest(request, context);

            // Assert
            assertEquals(JOURNEY_NEXT.getJourney(), response.get("journey"));
            verify(ipvSessionService).updateIpvSession(ipvSessionItem);
        }

        @Test
        void shouldHandleStoreIdentityProcessIdentityTypeAndReturnJourneyNextWhenTicfIsDisabled()
                throws Exception {
            // Arrange
            var request =
                    requestBuilder
                            .lambdaInput(
                                    Map.of(
                                            "processIdentityType",
                                            ProcessIdentityType.STORE_IDENTITY.name(),
                                            "identityType",
                                            IdentityType.NEW.name()))
                            .build();
            when(configService.getBooleanParameter(CREDENTIAL_ISSUER_ENABLED, Cri.TICF.getId()))
                    .thenReturn(false);

            when(identityProcessingService.getJourneyResponseFromStoringIdentity(
                            ipvSessionItem,
                            clientOAuthSessionItem,
                            IdentityType.NEW,
                            DEVICE_INFORMATION,
                            IP_ADDRESS))
                    .thenReturn(JOURNEY_NEXT);

            // Act
            var response = processCandidateIdentityHandler.handleRequest(request, context);

            // Assert
            assertEquals(JOURNEY_NEXT.getJourney(), response.get("journey"));
            verify(ipvSessionService).updateIpvSession(ipvSessionItem);
        }

        @Test
        void shouldReturnJourneyErrorIfIdentityTypeIsInvalid() throws Exception {
            // Arrange
            var request =
                    requestBuilder
                            .lambdaInput(
                                    Map.of(
                                            "processIdentityType",
                                            ProcessIdentityType.STORE_IDENTITY.name(),
                                            "identityType",
                                            "invalid-identity-type"))
                            .build();

            // Act
            var response = processCandidateIdentityHandler.handleRequest(request, context);

            // Assert
            assertEquals(JOURNEY_ERROR_PATH, response.get("journey"));
            assertEquals(400, response.get("statusCode"));
            assertEquals(INVALID_IDENTITY_TYPE_PARAMETER.getMessage(), response.get("message"));
        }

        @Test
        void shouldReturnJourneyErrorIfIdentityTypeIsNotProvided() throws Exception {
            // Arrange
            var request =
                    requestBuilder
                            .lambdaInput(
                                    Map.of(
                                            "processIdentityType",
                                            ProcessIdentityType.STORE_IDENTITY.name()))
                            .build();

            // Act
            var response = processCandidateIdentityHandler.handleRequest(request, context);

            // Assert
            assertEquals(JOURNEY_ERROR_PATH, response.get("journey"));
            assertEquals(400, response.get("statusCode"));
            assertEquals(INVALID_IDENTITY_TYPE_PARAMETER.getMessage(), response.get("message"));
        }
    }

    @Nested
    class processIdentityTypeTicfOnly {
        @BeforeEach
        void setUp() throws Exception {
            when(ipvSessionService.getIpvSession(SESSION_ID)).thenReturn(ipvSessionItem);
            when(clientOAuthSessionDetailsService.getClientOAuthSession(any()))
                    .thenReturn(clientOAuthSessionItem);
        }

        @Test
        void shouldHandleTicfOnlyProcessIdentityTypeAndReturnJourneyNext() throws Exception {
            // Arrange
            var request =
                    requestBuilder
                            .lambdaInput(
                                    Map.of(
                                            "processIdentityType",
                                            ProcessIdentityType.TICF_ONLY.name()))
                            .build();

            when(identityProcessingService.getJourneyResponseFromTicfCall(
                            ipvSessionItem, clientOAuthSessionItem, DEVICE_INFORMATION, IP_ADDRESS))
                    .thenReturn(JOURNEY_NEXT);

            // Act
            var response = processCandidateIdentityHandler.handleRequest(request, context);

            // Assert
            assertEquals(JOURNEY_NEXT.getJourney(), response.get("journey"));
            verify(ipvSessionService).updateIpvSession(ipvSessionItem);
        }
    }

    @Test
    void shouldReturnJourneyErrorIfIpvSessionNotFound() throws Exception {
        // Arrange
        var request =
                requestBuilder
                        .lambdaInput(
                                Map.of("processIdentityType", ProcessIdentityType.TICF_ONLY.name()))
                        .build();

        when(ipvSessionService.getIpvSession(SESSION_ID))
                .thenThrow(new IpvSessionNotFoundException("Oh no"));

        // Act
        var response = processCandidateIdentityHandler.handleRequest(request, context);

        // Assert
        assertEquals(JOURNEY_ERROR_PATH, response.get("journey"));
        assertEquals(500, response.get("statusCode"));
        assertEquals(IPV_SESSION_NOT_FOUND.getMessage(), response.get("message"));
    }

    @Test
    void shouldReturnJourneyErrorIfProcessIdentityTypeIsNotProvided() throws Exception {
        // Arrange
        var request =
                requestBuilder
                        .lambdaInput(Map.of("checkType", CoiCheckType.FULL_NAME_AND_DOB))
                        .build();

        // Act
        var response = processCandidateIdentityHandler.handleRequest(request, context);

        // Assert
        assertEquals(JOURNEY_ERROR_PATH, response.get("journey"));
        assertEquals(400, response.get("statusCode"));
        assertEquals(MISSING_PROCESS_IDENTITY_TYPE.getMessage(), response.get("message"));
    }

    @Test
    void shouldLogRuntimeExceptionsAndRethrow() throws Exception {
        // Arrange
        when(ipvSessionService.getIpvSession(anyString()))
                .thenThrow(new RuntimeException("Test error"));

        var logCollector = LogCollector.getLogCollectorFor(ProcessCandidateIdentityHandler.class);
        var request =
                requestBuilder
                        .lambdaInput(Map.of("processIdentityType", ProcessIdentityType.ALL.name()))
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
