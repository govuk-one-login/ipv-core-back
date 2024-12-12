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
import uk.gov.di.ipv.core.library.domain.JourneyResponse;
import uk.gov.di.ipv.core.library.domain.ProcessRequest;
import uk.gov.di.ipv.core.library.enums.IdentityType;
import uk.gov.di.ipv.core.library.enums.ProcessIdentityType;
import uk.gov.di.ipv.core.library.exception.EvcsServiceException;
import uk.gov.di.ipv.core.library.exceptions.CredentialParseException;
import uk.gov.di.ipv.core.library.exceptions.HttpResponseExceptionWithErrorBody;
import uk.gov.di.ipv.core.library.exceptions.VerifiableCredentialException;
import uk.gov.di.ipv.core.library.persistence.item.ClientOAuthSessionItem;
import uk.gov.di.ipv.core.library.persistence.item.IpvSessionItem;
import uk.gov.di.ipv.core.library.service.*;
import uk.gov.di.ipv.core.library.verifiablecredential.service.SessionCredentialsService;
import uk.gov.di.ipv.core.processcandidateidentity.service.CheckCoiService;
import uk.gov.di.ipv.core.processcandidateidentity.service.EvaluateGpg45ScoresService;
import uk.gov.di.ipv.core.processcandidateidentity.service.StoreIdentityService;

import java.util.List;
import java.util.Map;
import java.util.Optional;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;
import static uk.gov.di.ipv.core.library.domain.ErrorResponse.INVALID_IDENTITY_TYPE_PARAMETER;
import static uk.gov.di.ipv.core.library.domain.ErrorResponse.MISSING_CHECK_TYPE;
import static uk.gov.di.ipv.core.library.domain.ErrorResponse.MISSING_PROCESS_IDENTITY_TYPE;
import static uk.gov.di.ipv.core.library.domain.ErrorResponse.UNKNOWN_CHECK_TYPE;
import static uk.gov.di.ipv.core.library.enums.CoiCheckType.GIVEN_OR_FAMILY_NAME_AND_DOB;
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
    private static final String GOVUK_SIGNIN_JOURNEYID = "journey-id";
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
    @InjectMocks ProcessCandidateIdentityHandler processCandidateIdentityHandler;

    @BeforeEach
    void setUp() throws Exception {
        requestBuilder =
                ProcessRequest.processRequestBuilder()
                        .ipvSessionId(SESSION_ID)
                        .ipAddress(IP_ADDRESS)
                        .deviceInformation(DEVICE_INFORMATION);

        clientOAuthSessionItem =
                ClientOAuthSessionItem.builder()
                        .userId(USER_ID)
                        .govukSigninJourneyId(SIGNIN_JOURNEY_ID)
                        .build();
    }

    @BeforeEach
    void setUpEach() {
        ipvSessionItem.setIpvSessionId(SESSION_ID);
        clientOAuthSessionItemBuilder =
                ClientOAuthSessionItem.builder()
                        .userId(USER_ID)
                        .govukSigninJourneyId(GOVUK_SIGNIN_JOURNEYID);
    }

    @Test
    void shouldReturnJourneyErrorIfIdentityTypeIsNotProvided() throws Exception {
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

    @Nested
    class processIdentityTypeNew {
        @BeforeEach
        void setUp() throws Exception {
            clientOAuthSessionItem = clientOAuthSessionItemBuilder.vtr(List.of("P2")).build();
            when(ipvSessionService.getIpvSession(SESSION_ID)).thenReturn(ipvSessionItem);
            when(clientOAuthSessionDetailsService.getClientOAuthSession(any()))
                    .thenReturn(clientOAuthSessionItem);
        }

        @Test
        void shouldHandleAllProcessIdentityTypeAndReturnJourneyNext()
                throws HttpResponseExceptionWithErrorBody, VerifiableCredentialException,
                        EvcsServiceException, CredentialParseException {
            // Arrange
            var request =
                    requestBuilder
                            .lambdaInput(
                                    Map.of(
                                            "processIdentityType",
                                            ProcessIdentityType.NEW.name(),
                                            "checkType",
                                            GIVEN_OR_FAMILY_NAME_AND_DOB.name(),
                                            "identityType",
                                            IdentityType.NEW.name()))
                            .build();

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
                                            ProcessIdentityType.NEW.name(),
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
                                            ProcessIdentityType.NEW.name(),
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

        //
        @Test
        void shouldReturnJourneyErrorIfIdentityTypeIsInvalid() throws Exception {
            // Arrange
            var request =
                    requestBuilder
                            .lambdaInput(
                                    Map.of(
                                            "processIdentityType",
                                            ProcessIdentityType.NEW.name(),
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
    }

    @Nested
    class processIdentityTypePending {
        @BeforeEach
        void setUp() throws Exception {
            clientOAuthSessionItem = clientOAuthSessionItemBuilder.vtr(List.of("P2")).build();
            when(ipvSessionService.getIpvSession(SESSION_ID)).thenReturn(ipvSessionItem);
            when(clientOAuthSessionDetailsService.getClientOAuthSession(any()))
                    .thenReturn(clientOAuthSessionItem);
        }

        //
        @Test
        void shouldReturnJourneyErrorIfIdentityTypeIsInvalid() throws Exception {
            // Arrange
            var request =
                    requestBuilder
                            .lambdaInput(
                                    Map.of(
                                            "processIdentityType",
                                            ProcessIdentityType.NEW.name(),
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
    }
}
