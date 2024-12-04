package uk.gov.di.ipv.core.processcandidateidentity.service;

import org.apache.http.HttpStatus;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.MethodSource;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import uk.gov.di.ipv.core.library.cimit.exception.CiPostMitigationsException;
import uk.gov.di.ipv.core.library.cimit.exception.CiPutException;
import uk.gov.di.ipv.core.library.cimit.exception.CiRetrievalException;
import uk.gov.di.ipv.core.library.cristoringservice.CriStoringService;
import uk.gov.di.ipv.core.library.domain.ErrorResponse;
import uk.gov.di.ipv.core.library.domain.JourneyErrorResponse;
import uk.gov.di.ipv.core.library.domain.JourneyResponse;
import uk.gov.di.ipv.core.library.domain.VerifiableCredential;
import uk.gov.di.ipv.core.library.enums.CoiCheckType;
import uk.gov.di.ipv.core.library.enums.IdentityType;
import uk.gov.di.ipv.core.library.enums.Vot;
import uk.gov.di.ipv.core.library.exception.EvcsServiceException;
import uk.gov.di.ipv.core.library.exceptions.ConfigException;
import uk.gov.di.ipv.core.library.exceptions.CredentialParseException;
import uk.gov.di.ipv.core.library.exceptions.ErrorResponseException;
import uk.gov.di.ipv.core.library.exceptions.HttpResponseExceptionWithErrorBody;
import uk.gov.di.ipv.core.library.exceptions.UnrecognisedVotException;
import uk.gov.di.ipv.core.library.exceptions.VerifiableCredentialException;
import uk.gov.di.ipv.core.library.journeys.JourneyUris;
import uk.gov.di.ipv.core.library.persistence.item.ClientOAuthSessionItem;
import uk.gov.di.ipv.core.library.persistence.item.IpvSessionItem;
import uk.gov.di.ipv.core.library.service.AuditService;
import uk.gov.di.ipv.core.library.service.CimitService;
import uk.gov.di.ipv.core.library.service.CimitUtilityService;
import uk.gov.di.ipv.core.library.service.UserIdentityService;
import uk.gov.di.ipv.core.library.verifiablecredential.service.SessionCredentialsService;
import uk.gov.di.ipv.core.processcandidateidentity.exception.TicfCriServiceException;

import java.util.List;
import java.util.Optional;
import java.util.stream.Stream;

import static org.apache.http.HttpStatus.SC_INTERNAL_SERVER_ERROR;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.doThrow;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;
import static uk.gov.di.ipv.core.library.domain.Cri.TICF;
import static uk.gov.di.ipv.core.library.domain.ErrorResponse.ERROR_PROCESSING_TICF_CRI_RESPONSE;
import static uk.gov.di.ipv.core.library.domain.ErrorResponse.FAILED_NAME_CORRELATION;
import static uk.gov.di.ipv.core.library.domain.ErrorResponse.FAILED_TO_GET_CREDENTIAL;
import static uk.gov.di.ipv.core.library.domain.ErrorResponse.FAILED_TO_PARSE_ISSUED_CREDENTIALS;
import static uk.gov.di.ipv.core.library.domain.ErrorResponse.FAILED_TO_STORE_IDENTITY;
import static uk.gov.di.ipv.core.library.gpg45.enums.Gpg45Profile.M1A;
import static uk.gov.di.ipv.core.library.journeys.JourneyUris.JOURNEY_COI_CHECK_FAILED_PATH;
import static uk.gov.di.ipv.core.library.journeys.JourneyUris.JOURNEY_ERROR_PATH;
import static uk.gov.di.ipv.core.library.journeys.JourneyUris.JOURNEY_FAIL_WITH_CI_PATH;
import static uk.gov.di.ipv.core.library.journeys.JourneyUris.JOURNEY_GPG45_UNMET_PATH;
import static uk.gov.di.ipv.core.library.journeys.JourneyUris.JOURNEY_NEXT_PATH;

@ExtendWith(MockitoExtension.class)
public class IdentityProcessServiceTest {
    private static final String DEVICE_INFORMATION = "device_information";
    private static final String IP_ADDRESS = "ip_address";
    private static final String USER_ID = "user-id";
    private static final String GOVUK_SIGNIN_JOURNEYID = "journey-id";
    private static final String SESSION_ID = "session-id";

    private static final JourneyResponse JOURNEY_NEXT = new JourneyResponse(JOURNEY_NEXT_PATH);
    private static final JourneyResponse JOURNEY_GPG45_UNMET =
            new JourneyResponse(JOURNEY_GPG45_UNMET_PATH);
    private static final JourneyResponse JOURNEY_VCS_NOT_CORRELATED =
            new JourneyResponse(JourneyUris.JOURNEY_VCS_NOT_CORRELATED);
    private static final JourneyResponse JOURNEY_COI_CHECK_FAILED =
            new JourneyResponse(JOURNEY_COI_CHECK_FAILED_PATH);
    private static final String JOURNEY_ENHANCED_VERIFICATION = "/journey/enhanced-verification";
    private static final JourneyResponse JOURNEY_FAIL_WITH_CI =
            new JourneyResponse(JOURNEY_FAIL_WITH_CI_PATH);

    @Mock private IpvSessionItem ipvSessionItem;
    @Mock private VerifiableCredential mockVerifiableCredential;
    @Mock private TicfCriService ticfCriService;
    @Mock private AuditService auditService;
    @Mock private CimitUtilityService cimitUtilityService;
    @Mock private CimitService cimitService;
    @Mock private EvaluateGpg45ScoresService evaluateGpg45ScoresService;
    @Mock private SessionCredentialsService sessionCredentialsService;
    @Mock private UserIdentityService userIdentityService;
    @Mock private StoreIdentityService storeIdentityService;
    @Mock private CheckCoiService checkCoiService;
    @Mock private CriStoringService criStoringService;
    @InjectMocks IdentityProcessingService identityProcessingService;

    private ClientOAuthSessionItem.ClientOAuthSessionItemBuilder clientOAuthSessionItemBuilder;

    @BeforeEach
    void setUpEach() {
        ipvSessionItem.setIpvSessionId(SESSION_ID);
        clientOAuthSessionItemBuilder =
                ClientOAuthSessionItem.builder()
                        .userId(USER_ID)
                        .govukSigninJourneyId(GOVUK_SIGNIN_JOURNEYID);
    }

    @Nested
    class getJourneyResponseFromTicfCall {
        private ClientOAuthSessionItem clientOAuthSessionItem;

        @BeforeEach
        void setUpEach() {
            clientOAuthSessionItem = clientOAuthSessionItemBuilder.build();
        }

        @Test
        void shouldReturnJourneyNextIfTicfReturnsNoVcs() throws Exception {
            // Assert
            when(ticfCriService.getTicfVc(clientOAuthSessionItem, ipvSessionItem))
                    .thenReturn(List.of());

            // Act
            var journeyResponse =
                    identityProcessingService.getJourneyResponseFromTicfCall(
                            ipvSessionItem, clientOAuthSessionItem, DEVICE_INFORMATION, IP_ADDRESS);

            // Assert
            assertEquals(JOURNEY_NEXT, journeyResponse);
        }

        @Test
        void shouldReturnJourneyNextIfNoBreachingCis() throws Exception {
            // Arrange
            when(ticfCriService.getTicfVc(clientOAuthSessionItem, ipvSessionItem))
                    .thenReturn(List.of(mockVerifiableCredential));

            // Act
            var res =
                    identityProcessingService.getJourneyResponseFromTicfCall(
                            ipvSessionItem, clientOAuthSessionItem, DEVICE_INFORMATION, IP_ADDRESS);

            // Assert
            assertEquals(JOURNEY_NEXT, res);
            verify(criStoringService)
                    .storeVcs(
                            TICF,
                            IP_ADDRESS,
                            DEVICE_INFORMATION,
                            List.of(mockVerifiableCredential),
                            clientOAuthSessionItem,
                            ipvSessionItem);
            verify(cimitService).getContraIndicators(USER_ID, GOVUK_SIGNIN_JOURNEYID, IP_ADDRESS);
        }

        @Test
        void shouldReturnJourneyFailWithCiIfBreachingCis() throws Exception {
            // Arrange
            when(ticfCriService.getTicfVc(clientOAuthSessionItem, ipvSessionItem))
                    .thenReturn(List.of(mockVerifiableCredential));
            when(cimitUtilityService.getMitigationJourneyIfBreaching(any(), any()))
                    .thenReturn(Optional.of(JOURNEY_FAIL_WITH_CI));

            // Act
            var res =
                    identityProcessingService.getJourneyResponseFromTicfCall(
                            ipvSessionItem, clientOAuthSessionItem, DEVICE_INFORMATION, IP_ADDRESS);

            // Assert
            assertEquals(JOURNEY_FAIL_WITH_CI, res);
            verify(criStoringService)
                    .storeVcs(
                            TICF,
                            IP_ADDRESS,
                            DEVICE_INFORMATION,
                            List.of(mockVerifiableCredential),
                            clientOAuthSessionItem,
                            ipvSessionItem);
            verify(cimitService).getContraIndicators(USER_ID, GOVUK_SIGNIN_JOURNEYID, IP_ADDRESS);
            verify(ipvSessionItem).setVot(Vot.P0);
        }

        @Test
        void shouldReturnJourneyErrorIfTicfCriThrowsException() throws Exception {
            // Arrange
            when(ticfCriService.getTicfVc(clientOAuthSessionItem, ipvSessionItem))
                    .thenThrow(new TicfCriServiceException("Ticf CRI errors"));

            // Act/Assert
            assertEquals(
                    new JourneyErrorResponse(
                            JOURNEY_ERROR_PATH,
                            HttpStatus.SC_INTERNAL_SERVER_ERROR,
                            ERROR_PROCESSING_TICF_CRI_RESPONSE),
                    identityProcessingService.getJourneyResponseFromTicfCall(
                            ipvSessionItem,
                            clientOAuthSessionItem,
                            DEVICE_INFORMATION,
                            IP_ADDRESS));
        }

        private static Stream<Exception> storeVcsExceptions() {
            return Stream.of(
                    new CiPutException("Oops"),
                    new CiPostMitigationsException("Oops"),
                    new VerifiableCredentialException(1, ErrorResponse.FAILED_TO_SAVE_CREDENTIAL),
                    new UnrecognisedVotException("Oops"));
        }

        @ParameterizedTest
        @MethodSource("storeVcsExceptions")
        void shouldReturnJourneyErrorIfCriStoringServiceThrowsVerifiableCredentialException(
                Exception e) throws Exception {
            // Arrange
            when(ticfCriService.getTicfVc(clientOAuthSessionItem, ipvSessionItem))
                    .thenReturn(List.of(mockVerifiableCredential));
            doThrow(e).when(criStoringService).storeVcs(any(), any(), any(), any(), any(), any());

            // Act
            var res =
                    identityProcessingService.getJourneyResponseFromTicfCall(
                            ipvSessionItem, clientOAuthSessionItem, DEVICE_INFORMATION, IP_ADDRESS);

            // Act/Assert
            assertEquals(
                    new JourneyErrorResponse(
                            JOURNEY_ERROR_PATH,
                            HttpStatus.SC_INTERNAL_SERVER_ERROR,
                            ERROR_PROCESSING_TICF_CRI_RESPONSE),
                    res);
        }

        @Test
        void shouldReturnJourneyErrorWhenGetContraIndicatorsThrowsCiRetrievalException()
                throws Exception {
            // Arrange
            when(ticfCriService.getTicfVc(clientOAuthSessionItem, ipvSessionItem))
                    .thenReturn(List.of(mockVerifiableCredential));
            when(cimitService.getContraIndicators(USER_ID, GOVUK_SIGNIN_JOURNEYID, IP_ADDRESS))
                    .thenThrow(new CiRetrievalException("Whoops"));

            // Act
            var res =
                    identityProcessingService.getJourneyResponseFromTicfCall(
                            ipvSessionItem, clientOAuthSessionItem, DEVICE_INFORMATION, IP_ADDRESS);

            // Act/Assert
            assertEquals(
                    new JourneyErrorResponse(
                            JOURNEY_ERROR_PATH,
                            HttpStatus.SC_INTERNAL_SERVER_ERROR,
                            ERROR_PROCESSING_TICF_CRI_RESPONSE),
                    res);
        }

        @Test
        void shouldReturnJourneyErrorWhenGgetMitigationJourneyIfBreachingThrowsConfigException()
                throws Exception {
            // Arrange
            when(ticfCriService.getTicfVc(clientOAuthSessionItem, ipvSessionItem))
                    .thenReturn(List.of(mockVerifiableCredential));
            when(cimitService.getContraIndicators(USER_ID, GOVUK_SIGNIN_JOURNEYID, IP_ADDRESS))
                    .thenReturn(List.of());
            when(cimitUtilityService.getMitigationJourneyIfBreaching(any(), any()))
                    .thenThrow(new ConfigException("Whoops"));

            // Act
            var res =
                    identityProcessingService.getJourneyResponseFromTicfCall(
                            ipvSessionItem, clientOAuthSessionItem, DEVICE_INFORMATION, IP_ADDRESS);

            // Act/Assert
            assertEquals(
                    new JourneyErrorResponse(
                            JOURNEY_ERROR_PATH,
                            HttpStatus.SC_INTERNAL_SERVER_ERROR,
                            ERROR_PROCESSING_TICF_CRI_RESPONSE),
                    res);
        }
    }

    @Nested
    class getJourneyResponseFromGpg45ScoreEvaluation {
        private ClientOAuthSessionItem clientOAuthSessionItem;

        @BeforeEach
        void setUpEach() {
            clientOAuthSessionItem = clientOAuthSessionItemBuilder.vtr(List.of("P2")).build();
        }

        @Test
        void shouldReturnJourneyNextIfGpg45ProfileIsMet() throws Exception {
            when(sessionCredentialsService.getCredentials(any(), any()))
                    .thenReturn(List.of(mockVerifiableCredential));
            when(userIdentityService.areVcsCorrelated(List.of(mockVerifiableCredential)))
                    .thenReturn(true);
            when(evaluateGpg45ScoresService.findMatchingGpg45Profile(
                            List.of(mockVerifiableCredential),
                            ipvSessionItem,
                            clientOAuthSessionItem,
                            IP_ADDRESS,
                            DEVICE_INFORMATION,
                            null))
                    .thenReturn(Optional.of(M1A));

            // Act
            var res =
                    identityProcessingService.getJourneyResponseFromGpg45ScoreEvaluation(
                            ipvSessionItem, clientOAuthSessionItem, DEVICE_INFORMATION, IP_ADDRESS);

            // Assert
            assertEquals(JOURNEY_NEXT, res);
            verify(cimitService, times(0))
                    .getContraIndicators(USER_ID, GOVUK_SIGNIN_JOURNEYID, IP_ADDRESS);
            verify(ipvSessionItem).setVot(Vot.P2);
        }

        @Test
        void shouldReturnJourneyVcsNotCorrelatedIfVcsAreNotCorrelated() throws Exception {
            when(sessionCredentialsService.getCredentials(any(), any()))
                    .thenReturn(List.of(mockVerifiableCredential));
            when(userIdentityService.areVcsCorrelated(List.of(mockVerifiableCredential)))
                    .thenReturn(false);

            // Act
            var res =
                    identityProcessingService.getJourneyResponseFromGpg45ScoreEvaluation(
                            ipvSessionItem, clientOAuthSessionItem, DEVICE_INFORMATION, IP_ADDRESS);

            // Assert
            assertEquals(JOURNEY_VCS_NOT_CORRELATED, res);
        }

        @Test
        void shouldReturnJourneyNextIfGpg45ProfilesAreNotMet() throws Exception {
            when(sessionCredentialsService.getCredentials(any(), any()))
                    .thenReturn(List.of(mockVerifiableCredential));
            when(userIdentityService.areVcsCorrelated(List.of(mockVerifiableCredential)))
                    .thenReturn(true);
            when(evaluateGpg45ScoresService.findMatchingGpg45Profile(
                            List.of(mockVerifiableCredential),
                            ipvSessionItem,
                            clientOAuthSessionItem,
                            IP_ADDRESS,
                            DEVICE_INFORMATION,
                            null))
                    .thenReturn(Optional.empty());

            // Act
            var res =
                    identityProcessingService.getJourneyResponseFromGpg45ScoreEvaluation(
                            ipvSessionItem, clientOAuthSessionItem, DEVICE_INFORMATION, IP_ADDRESS);

            // Assert
            assertEquals(JOURNEY_GPG45_UNMET, res);
            verify(cimitService, times(0))
                    .getContraIndicators(USER_ID, GOVUK_SIGNIN_JOURNEYID, IP_ADDRESS);
        }

        @Test
        void shouldOnlyGetContraIndicatorsIfMoreThanOneVtr() throws Exception {
            // Arrange
            var clientOAuthSessionItem =
                    ClientOAuthSessionItem.builder()
                            .userId(USER_ID)
                            .govukSigninJourneyId(GOVUK_SIGNIN_JOURNEYID)
                            .vtr(List.of("P2", "P1"))
                            .build();
            when(sessionCredentialsService.getCredentials(any(), any()))
                    .thenReturn(List.of(mockVerifiableCredential));
            when(userIdentityService.areVcsCorrelated(List.of(mockVerifiableCredential)))
                    .thenReturn(true);
            when(cimitService.getContraIndicators(USER_ID, GOVUK_SIGNIN_JOURNEYID, IP_ADDRESS))
                    .thenReturn(List.of());
            when(evaluateGpg45ScoresService.findMatchingGpg45Profile(
                            List.of(mockVerifiableCredential),
                            ipvSessionItem,
                            clientOAuthSessionItem,
                            IP_ADDRESS,
                            DEVICE_INFORMATION,
                            List.of()))
                    .thenReturn(Optional.of(M1A));

            // Act
            var res =
                    identityProcessingService.getJourneyResponseFromGpg45ScoreEvaluation(
                            ipvSessionItem, clientOAuthSessionItem, DEVICE_INFORMATION, IP_ADDRESS);

            // Assert
            assertEquals(JOURNEY_NEXT, res);
            verify(cimitService, times(1))
                    .getContraIndicators(USER_ID, GOVUK_SIGNIN_JOURNEYID, IP_ADDRESS);
        }

        @Test
        void shouldReturnJourneyErrorIfGetCredentialsThrowsVerifiableCredentialException()
                throws Exception {
            // Arrange
            when(sessionCredentialsService.getCredentials(any(), any()))
                    .thenThrow(
                            new VerifiableCredentialException(
                                    1, ErrorResponse.FAILED_TO_GET_CREDENTIAL));

            // Act
            var res =
                    identityProcessingService.getJourneyResponseFromGpg45ScoreEvaluation(
                            ipvSessionItem, clientOAuthSessionItem, DEVICE_INFORMATION, IP_ADDRESS);

            // Assert
            assertEquals(
                    new JourneyErrorResponse(
                            JOURNEY_ERROR_PATH, 1, ErrorResponse.FAILED_TO_GET_CREDENTIAL),
                    res);
        }

        @Test
        void shouldReturnJourneyErrorIfAreVcsCorrelatedThrowsHttpResponseExceptionWithErrorBody()
                throws Exception {
            // Arrange
            when(sessionCredentialsService.getCredentials(any(), any()))
                    .thenReturn(List.of(mockVerifiableCredential));
            when(userIdentityService.areVcsCorrelated(List.of(mockVerifiableCredential)))
                    .thenThrow(
                            new HttpResponseExceptionWithErrorBody(
                                    1, ErrorResponse.FAILED_NAME_CORRELATION));

            // Act
            var res =
                    identityProcessingService.getJourneyResponseFromGpg45ScoreEvaluation(
                            ipvSessionItem, clientOAuthSessionItem, DEVICE_INFORMATION, IP_ADDRESS);

            // Assert
            assertEquals(
                    new JourneyErrorResponse(
                            JOURNEY_ERROR_PATH, 1, ErrorResponse.FAILED_NAME_CORRELATION),
                    res);
        }

        @Test
        void shouldReturnJourneyErrorIfGetContraIndicatorsThrowsCiRetrievalException()
                throws Exception {
            // Arrange
            var clientOAuthSessionItem =
                    ClientOAuthSessionItem.builder()
                            .userId(USER_ID)
                            .govukSigninJourneyId(GOVUK_SIGNIN_JOURNEYID)
                            .vtr(List.of("P2", "P1"))
                            .build();
            when(sessionCredentialsService.getCredentials(any(), any()))
                    .thenReturn(List.of(mockVerifiableCredential));
            when(userIdentityService.areVcsCorrelated(List.of(mockVerifiableCredential)))
                    .thenReturn(true);
            when(cimitService.getContraIndicators(USER_ID, GOVUK_SIGNIN_JOURNEYID, IP_ADDRESS))
                    .thenThrow(new CiRetrievalException("Whoops"));

            // Act
            var res =
                    identityProcessingService.getJourneyResponseFromGpg45ScoreEvaluation(
                            ipvSessionItem, clientOAuthSessionItem, DEVICE_INFORMATION, IP_ADDRESS);

            // Assert
            assertEquals(
                    new JourneyErrorResponse(
                            JOURNEY_ERROR_PATH,
                            HttpStatus.SC_INTERNAL_SERVER_ERROR,
                            ErrorResponse.FAILED_TO_GET_STORED_CIS),
                    res);
        }
    }

    @Nested
    class getJourneyResponseFromStoringIdentity {
        private ClientOAuthSessionItem clientOAuthSessionItem;

        @BeforeEach
        void setUpEach() {
            clientOAuthSessionItem = clientOAuthSessionItemBuilder.build();
        }

        @Test
        void shouldReturnJourneyNextIfStoreIdentityIsSuccessful() throws Exception {
            // Act
            var res =
                    identityProcessingService.getJourneyResponseFromStoringIdentity(
                            ipvSessionItem,
                            clientOAuthSessionItem,
                            IdentityType.NEW,
                            DEVICE_INFORMATION,
                            IP_ADDRESS);

            // Assert
            assertEquals(JOURNEY_NEXT, res);
        }

        private static Stream<ErrorResponseException> storeIdentityExceptions() {
            return Stream.of(
                    new VerifiableCredentialException(1, FAILED_TO_GET_CREDENTIAL),
                    new EvcsServiceException(1, FAILED_TO_STORE_IDENTITY));
        }

        @ParameterizedTest
        @MethodSource("storeIdentityExceptions")
        void shouldReturnErrorJourneyWhenStoreIdentityThrowsAnException(ErrorResponseException e)
                throws Exception {
            // Arrange
            doThrow((Throwable) e)
                    .when(storeIdentityService)
                    .storeIdentity(
                            ipvSessionItem,
                            clientOAuthSessionItem,
                            IdentityType.NEW,
                            DEVICE_INFORMATION,
                            IP_ADDRESS);

            // Act
            var res =
                    identityProcessingService.getJourneyResponseFromStoringIdentity(
                            ipvSessionItem,
                            clientOAuthSessionItem,
                            IdentityType.NEW,
                            DEVICE_INFORMATION,
                            IP_ADDRESS);

            // Assert
            assertEquals(
                    new JourneyErrorResponse(
                            JOURNEY_ERROR_PATH, e.getResponseCode(), e.getErrorResponse()),
                    res);
        }
    }

    @Nested
    class getJourneyResponseFromCoiCheck {
        private ClientOAuthSessionItem clientOAuthSessionItem;

        @BeforeEach
        void setUpEach() {
            clientOAuthSessionItem = clientOAuthSessionItemBuilder.build();
        }

        @Test
        void shouldReturnJourneyNextIfCoiCheckIsSuccessful() throws Exception {
            // Arrange
            when(checkCoiService.isCoiCheckSuccessful(
                            ipvSessionItem,
                            clientOAuthSessionItem,
                            CoiCheckType.GIVEN_OR_FAMILY_NAME_AND_DOB,
                            DEVICE_INFORMATION,
                            IP_ADDRESS))
                    .thenReturn(true);

            // Act
            var res =
                    identityProcessingService.getJourneyResponseFromCoiCheck(
                            ipvSessionItem,
                            clientOAuthSessionItem,
                            CoiCheckType.GIVEN_OR_FAMILY_NAME_AND_DOB,
                            DEVICE_INFORMATION,
                            IP_ADDRESS);

            // Assert
            assertEquals(JOURNEY_NEXT, res);
        }

        @Test
        void shouldReturnJourneyNextIfCoiCheckIsNotSuccessful() throws Exception {
            // Arrange
            when(checkCoiService.isCoiCheckSuccessful(
                            ipvSessionItem,
                            clientOAuthSessionItem,
                            CoiCheckType.GIVEN_OR_FAMILY_NAME_AND_DOB,
                            DEVICE_INFORMATION,
                            IP_ADDRESS))
                    .thenReturn(false);

            // Act
            var res =
                    identityProcessingService.getJourneyResponseFromCoiCheck(
                            ipvSessionItem,
                            clientOAuthSessionItem,
                            CoiCheckType.GIVEN_OR_FAMILY_NAME_AND_DOB,
                            DEVICE_INFORMATION,
                            IP_ADDRESS);

            // Assert
            assertEquals(JOURNEY_COI_CHECK_FAILED, res);
        }

        @Test
        void shouldReturnJourneyErrorIsCoiCheckSuccessfulThrowsCredentialParseException()
                throws Exception {
            // Arrange
            when(checkCoiService.isCoiCheckSuccessful(
                            ipvSessionItem,
                            clientOAuthSessionItem,
                            CoiCheckType.GIVEN_OR_FAMILY_NAME_AND_DOB,
                            DEVICE_INFORMATION,
                            IP_ADDRESS))
                    .thenThrow(new CredentialParseException("Whoops"));

            // Act
            var res =
                    identityProcessingService.getJourneyResponseFromCoiCheck(
                            ipvSessionItem,
                            clientOAuthSessionItem,
                            CoiCheckType.GIVEN_OR_FAMILY_NAME_AND_DOB,
                            DEVICE_INFORMATION,
                            IP_ADDRESS);

            // Assert
            assertEquals(
                    new JourneyErrorResponse(
                            JOURNEY_ERROR_PATH,
                            SC_INTERNAL_SERVER_ERROR,
                            FAILED_TO_PARSE_ISSUED_CREDENTIALS),
                    res);
        }

        private static Stream<ErrorResponseException> isCoiCheckSuccessfulExceptions() {
            return Stream.of(
                    new VerifiableCredentialException(1, FAILED_TO_GET_CREDENTIAL),
                    new EvcsServiceException(1, FAILED_TO_STORE_IDENTITY),
                    new HttpResponseExceptionWithErrorBody(1, FAILED_NAME_CORRELATION));
        }

        @ParameterizedTest
        @MethodSource("isCoiCheckSuccessfulExceptions")
        void shouldReturnErrorJourneyWhenStoreIdentityThrowsAnException(ErrorResponseException e)
                throws Exception {
            // Arrange
            when(checkCoiService.isCoiCheckSuccessful(
                            ipvSessionItem,
                            clientOAuthSessionItem,
                            CoiCheckType.GIVEN_OR_FAMILY_NAME_AND_DOB,
                            DEVICE_INFORMATION,
                            IP_ADDRESS))
                    .thenThrow((Throwable) e);

            // Act
            var res =
                    identityProcessingService.getJourneyResponseFromCoiCheck(
                            ipvSessionItem,
                            clientOAuthSessionItem,
                            CoiCheckType.GIVEN_OR_FAMILY_NAME_AND_DOB,
                            DEVICE_INFORMATION,
                            IP_ADDRESS);

            // Assert
            assertEquals(
                    new JourneyErrorResponse(
                            JOURNEY_ERROR_PATH, e.getResponseCode(), e.getErrorResponse()),
                    res);
        }
    }
}
