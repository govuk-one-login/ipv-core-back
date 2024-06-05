package uk.gov.di.ipv.core.checkcoi;

import com.amazonaws.services.lambda.runtime.Context;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.EnumSource;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.mockito.junit.jupiter.MockitoSettings;
import uk.gov.di.ipv.core.library.domain.CoiSubjourneyType;
import uk.gov.di.ipv.core.library.domain.ProcessRequest;
import uk.gov.di.ipv.core.library.exceptions.CredentialParseException;
import uk.gov.di.ipv.core.library.exceptions.HttpResponseExceptionWithErrorBody;
import uk.gov.di.ipv.core.library.exceptions.VerifiableCredentialException;
import uk.gov.di.ipv.core.library.persistence.item.ClientOAuthSessionItem;
import uk.gov.di.ipv.core.library.persistence.item.IpvSessionItem;
import uk.gov.di.ipv.core.library.service.ClientOAuthSessionDetailsService;
import uk.gov.di.ipv.core.library.service.ConfigService;
import uk.gov.di.ipv.core.library.service.IpvSessionService;
import uk.gov.di.ipv.core.library.service.UserIdentityService;
import uk.gov.di.ipv.core.library.verifiablecredential.service.SessionCredentialsService;
import uk.gov.di.ipv.core.library.verifiablecredential.service.VerifiableCredentialService;

import java.util.List;

import static com.nimbusds.oauth2.sdk.http.HTTPResponse.SC_SERVER_ERROR;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.mockito.Mockito.when;
import static org.mockito.quality.Strictness.LENIENT;
import static uk.gov.di.ipv.core.library.domain.CoiSubjourneyType.ADDRESS_ONLY;
import static uk.gov.di.ipv.core.library.domain.CoiSubjourneyType.REVERIFICATION;
import static uk.gov.di.ipv.core.library.domain.ErrorResponse.FAILED_NAME_CORRELATION;
import static uk.gov.di.ipv.core.library.domain.ErrorResponse.FAILED_TO_GET_CREDENTIAL;
import static uk.gov.di.ipv.core.library.domain.ErrorResponse.FAILED_TO_PARSE_ISSUED_CREDENTIALS;
import static uk.gov.di.ipv.core.library.domain.ErrorResponse.MISSING_IPV_SESSION_ID;
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
    @Mock private ConfigService mockConfigService;
    @Mock private IpvSessionService mockIpvSessionService;
    @Mock private ClientOAuthSessionDetailsService mockClientSessionService;
    @Mock private VerifiableCredentialService mockVerifiableCredentialService;
    @Mock private SessionCredentialsService mockSessionCredentialService;
    @Mock private UserIdentityService mockUserIdentityService;
    @Mock private Context mockContext;
    @Mock private IpvSessionItem mockIpvSessionItem;
    @Mock private ClientOAuthSessionItem mockClientSessionItem;
    @InjectMocks CheckCoiHandler checkCoiHandler;

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
        @Nested
        @DisplayName("Successful checks")
        class SuccessfulChecks {
            @ParameterizedTest
            @EnumSource(
                    value = CoiSubjourneyType.class,
                    names = {"GIVEN_NAMES_ONLY", "GIVEN_NAMES_AND_ADDRESS"})
            void shouldReturnPassedForSuccessfulGivenNamesOnlyCheck(
                    CoiSubjourneyType coiSubjourneyType) throws Exception {
                when(mockUserIdentityService.areFamilyNameAndDobCorrelatedForCoiCheck(
                                List.of(M1A_ADDRESS_VC, M1A_EXPERIAN_FRAUD_VC)))
                        .thenReturn(true);
                when(mockIpvSessionItem.getCoiSubjourneyType()).thenReturn(coiSubjourneyType);

                var request =
                        ProcessRequest.processRequestBuilder().ipvSessionId(IPV_SESSION_ID).build();

                var responseMap = checkCoiHandler.handleRequest(request, mockContext);

                assertEquals(JOURNEY_COI_CHECK_PASSED_PATH, responseMap.get("journey"));
            }

            @ParameterizedTest
            @EnumSource(
                    value = CoiSubjourneyType.class,
                    names = {"FAMILY_NAME_ONLY", "FAMILY_NAME_AND_ADDRESS"})
            void shouldReturnPassedForSuccessfulFamilyNameOnlyCheck(
                    CoiSubjourneyType coiSubjourneyType) throws Exception {
                when(mockUserIdentityService.areGivenNamesAndDobCorrelated(
                                List.of(M1A_ADDRESS_VC, M1A_EXPERIAN_FRAUD_VC)))
                        .thenReturn(true);
                when(mockIpvSessionItem.getCoiSubjourneyType()).thenReturn(coiSubjourneyType);

                var request =
                        ProcessRequest.processRequestBuilder().ipvSessionId(IPV_SESSION_ID).build();

                var responseMap = checkCoiHandler.handleRequest(request, mockContext);

                assertEquals(JOURNEY_COI_CHECK_PASSED_PATH, responseMap.get("journey"));
            }

            @Test
            void shouldReturnPassedForAddressOnlyCheck() {
                when(mockIpvSessionItem.getCoiSubjourneyType()).thenReturn(ADDRESS_ONLY);

                var request =
                        ProcessRequest.processRequestBuilder().ipvSessionId(IPV_SESSION_ID).build();

                var responseMap = checkCoiHandler.handleRequest(request, mockContext);

                assertEquals(JOURNEY_COI_CHECK_PASSED_PATH, responseMap.get("journey"));
            }

            @Test
            void shouldReturnPassedForSuccessfulReverificationCheck()
                    throws HttpResponseExceptionWithErrorBody, CredentialParseException {
                when(mockUserIdentityService.areVcsCorrelated(
                                List.of(M1A_ADDRESS_VC, M1A_EXPERIAN_FRAUD_VC)))
                        .thenReturn(true);
                when(mockIpvSessionItem.getCoiSubjourneyType()).thenReturn(REVERIFICATION);

                var request =
                        ProcessRequest.processRequestBuilder().ipvSessionId(IPV_SESSION_ID).build();

                var responseMap = checkCoiHandler.handleRequest(request, mockContext);

                assertEquals(JOURNEY_COI_CHECK_PASSED_PATH, responseMap.get("journey"));
            }
        }

        @Nested
        @DisplayName("Failed checks")
        class FailedChecks {
            @ParameterizedTest
            @EnumSource(
                    value = CoiSubjourneyType.class,
                    names = {"GIVEN_NAMES_ONLY", "GIVEN_NAMES_AND_ADDRESS"})
            void shouldReturnFailedForFailedGivenNamesOnlyCheck(CoiSubjourneyType coiSubjourneyType)
                    throws Exception {
                when(mockUserIdentityService.areFamilyNameAndDobCorrelatedForCoiCheck(
                                List.of(M1A_ADDRESS_VC, M1A_EXPERIAN_FRAUD_VC)))
                        .thenReturn(false);
                when(mockIpvSessionItem.getCoiSubjourneyType()).thenReturn(coiSubjourneyType);

                var request =
                        ProcessRequest.processRequestBuilder().ipvSessionId(IPV_SESSION_ID).build();

                var responseMap = checkCoiHandler.handleRequest(request, mockContext);

                assertEquals(JOURNEY_COI_CHECK_FAILED_PATH, responseMap.get("journey"));
            }

            @ParameterizedTest
            @EnumSource(
                    value = CoiSubjourneyType.class,
                    names = {"FAMILY_NAME_ONLY", "FAMILY_NAME_AND_ADDRESS"})
            void shouldReturnFailedForFailedFamilyNameOnlyCheck(CoiSubjourneyType coiSubjourneyType)
                    throws Exception {
                when(mockUserIdentityService.areGivenNamesAndDobCorrelated(
                                List.of(M1A_ADDRESS_VC, M1A_EXPERIAN_FRAUD_VC)))
                        .thenReturn(false);
                when(mockIpvSessionItem.getCoiSubjourneyType()).thenReturn(coiSubjourneyType);

                var request =
                        ProcessRequest.processRequestBuilder().ipvSessionId(IPV_SESSION_ID).build();

                var responseMap = checkCoiHandler.handleRequest(request, mockContext);

                assertEquals(JOURNEY_COI_CHECK_FAILED_PATH, responseMap.get("journey"));
            }
        }
    }

    @Nested
    @DisplayName("Errors")
    class Errors {

        @Test
        @MockitoSettings(strictness = LENIENT)
        void shouldReturnErrorIfIpvSessionIdNotFound() {
            var request = ProcessRequest.processRequestBuilder().ipvSessionId(null).build();

            var responseMap = checkCoiHandler.handleRequest(request, mockContext);

            assertEquals(JOURNEY_ERROR_PATH, responseMap.get("journey"));
            assertEquals(MISSING_IPV_SESSION_ID.getMessage(), responseMap.get("message"));
        }

        @ParameterizedTest
        @EnumSource(
                value = CoiSubjourneyType.class,
                names = {"GIVEN_NAMES_ONLY", "GIVEN_NAMES_AND_ADDRESS"})
        void shouldReturnErrorIfFamilyNameCorrelationCheckThrowsHttpResponseException(
                CoiSubjourneyType coiSubjourneyType) throws Exception {
            when(mockUserIdentityService.areFamilyNameAndDobCorrelatedForCoiCheck(
                            List.of(M1A_ADDRESS_VC, M1A_EXPERIAN_FRAUD_VC)))
                    .thenThrow(
                            new HttpResponseExceptionWithErrorBody(
                                    SC_SERVER_ERROR, FAILED_NAME_CORRELATION));
            when(mockIpvSessionItem.getCoiSubjourneyType()).thenReturn(coiSubjourneyType);

            var request =
                    ProcessRequest.processRequestBuilder().ipvSessionId(IPV_SESSION_ID).build();

            var responseMap = checkCoiHandler.handleRequest(request, mockContext);

            assertEquals(JOURNEY_ERROR_PATH, responseMap.get("journey"));
            assertEquals(FAILED_NAME_CORRELATION.getMessage(), responseMap.get("message"));
        }

        @ParameterizedTest
        @EnumSource(
                value = CoiSubjourneyType.class,
                names = {"FAMILY_NAME_ONLY", "FAMILY_NAME_AND_ADDRESS"})
        void shouldReturnErrorIfGivenNameCorrelationCheckThrowsHttpResponseException(
                CoiSubjourneyType coiSubjourneyType) throws Exception {
            when(mockUserIdentityService.areGivenNamesAndDobCorrelated(
                            List.of(M1A_ADDRESS_VC, M1A_EXPERIAN_FRAUD_VC)))
                    .thenThrow(
                            new HttpResponseExceptionWithErrorBody(
                                    SC_SERVER_ERROR, FAILED_NAME_CORRELATION));
            when(mockIpvSessionItem.getCoiSubjourneyType()).thenReturn(coiSubjourneyType);

            var request =
                    ProcessRequest.processRequestBuilder().ipvSessionId(IPV_SESSION_ID).build();

            var responseMap = checkCoiHandler.handleRequest(request, mockContext);

            assertEquals(JOURNEY_ERROR_PATH, responseMap.get("journey"));
            assertEquals(FAILED_NAME_CORRELATION.getMessage(), responseMap.get("message"));
        }

        @ParameterizedTest
        @EnumSource(
                value = CoiSubjourneyType.class,
                names = {"GIVEN_NAMES_ONLY", "GIVEN_NAMES_AND_ADDRESS"})
        void shouldReturnErrorIfFamilyNameCorrelationCheckThrowsVerifiableCredentialException(
                CoiSubjourneyType coiSubjourneyType) throws Exception {
            when(mockUserIdentityService.areFamilyNameAndDobCorrelatedForCoiCheck(
                            List.of(M1A_ADDRESS_VC, M1A_EXPERIAN_FRAUD_VC)))
                    .thenThrow(new CredentialParseException("oops"));
            when(mockIpvSessionItem.getCoiSubjourneyType()).thenReturn(coiSubjourneyType);

            var request =
                    ProcessRequest.processRequestBuilder().ipvSessionId(IPV_SESSION_ID).build();

            var responseMap = checkCoiHandler.handleRequest(request, mockContext);

            assertEquals(JOURNEY_ERROR_PATH, responseMap.get("journey"));
            assertEquals(
                    FAILED_TO_PARSE_ISSUED_CREDENTIALS.getMessage(), responseMap.get("message"));
        }

        @ParameterizedTest
        @EnumSource(
                value = CoiSubjourneyType.class,
                names = {"FAMILY_NAME_ONLY", "FAMILY_NAME_AND_ADDRESS"})
        void shouldReturnErrorIfGivenNameCorrelationCheckThrowsCredParseException(
                CoiSubjourneyType coiSubjourneyType) throws Exception {
            when(mockUserIdentityService.areGivenNamesAndDobCorrelated(
                            List.of(M1A_ADDRESS_VC, M1A_EXPERIAN_FRAUD_VC)))
                    .thenThrow(new CredentialParseException("oops"));
            when(mockIpvSessionItem.getCoiSubjourneyType()).thenReturn(coiSubjourneyType);

            var request =
                    ProcessRequest.processRequestBuilder().ipvSessionId(IPV_SESSION_ID).build();

            var responseMap = checkCoiHandler.handleRequest(request, mockContext);

            assertEquals(JOURNEY_ERROR_PATH, responseMap.get("journey"));
            assertEquals(
                    FAILED_TO_PARSE_ISSUED_CREDENTIALS.getMessage(), responseMap.get("message"));
        }

        @Test
        void shouldReturnErrorIfAreVcsCorrelatedCheckThrowsHttpResponseException()
                throws Exception {
            when(mockUserIdentityService.areVcsCorrelated(
                            List.of(M1A_ADDRESS_VC, M1A_EXPERIAN_FRAUD_VC)))
                    .thenThrow(
                            new HttpResponseExceptionWithErrorBody(
                                    SC_SERVER_ERROR, FAILED_NAME_CORRELATION));
            when(mockIpvSessionItem.getCoiSubjourneyType()).thenReturn(REVERIFICATION);

            var request =
                    ProcessRequest.processRequestBuilder().ipvSessionId(IPV_SESSION_ID).build();

            var responseMap = checkCoiHandler.handleRequest(request, mockContext);

            assertEquals(JOURNEY_ERROR_PATH, responseMap.get("journey"));
            assertEquals(FAILED_NAME_CORRELATION.getMessage(), responseMap.get("message"));
        }

        @Test
        void shouldReturnErrorIfAreVcsCorrelatedCheckThrowsCredentialParseException()
                throws Exception {
            when(mockUserIdentityService.areVcsCorrelated(
                            List.of(M1A_ADDRESS_VC, M1A_EXPERIAN_FRAUD_VC)))
                    .thenThrow(new CredentialParseException("oops"));
            when(mockIpvSessionItem.getCoiSubjourneyType()).thenReturn(REVERIFICATION);

            var request =
                    ProcessRequest.processRequestBuilder().ipvSessionId(IPV_SESSION_ID).build();

            var responseMap = checkCoiHandler.handleRequest(request, mockContext);

            assertEquals(JOURNEY_ERROR_PATH, responseMap.get("journey"));
            assertEquals(
                    FAILED_TO_PARSE_ISSUED_CREDENTIALS.getMessage(), responseMap.get("message"));
        }

        @Test
        void shouldReturnErrorIfGettingSessionCredentialsThrows() throws Exception {
            when(mockSessionCredentialService.getCredentials(IPV_SESSION_ID, USER_ID))
                    .thenThrow(
                            new VerifiableCredentialException(
                                    SC_SERVER_ERROR, FAILED_TO_GET_CREDENTIAL));

            var request =
                    ProcessRequest.processRequestBuilder().ipvSessionId(IPV_SESSION_ID).build();

            var responseMap = checkCoiHandler.handleRequest(request, mockContext);

            assertEquals(JOURNEY_ERROR_PATH, responseMap.get("journey"));
            assertEquals(FAILED_TO_GET_CREDENTIAL.getMessage(), responseMap.get("message"));
        }
    }
}
