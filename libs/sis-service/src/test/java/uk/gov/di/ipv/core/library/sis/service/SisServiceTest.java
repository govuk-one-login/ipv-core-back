package uk.gov.di.ipv.core.library.sis.service;

import com.nimbusds.jwt.SignedJWT;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.ArgumentCaptor;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import uk.gov.di.ipv.core.library.auditing.AuditEvent;
import uk.gov.di.ipv.core.library.auditing.AuditEventUser;
import uk.gov.di.ipv.core.library.criresponse.service.CriResponseService;
import uk.gov.di.ipv.core.library.domain.Cri;
import uk.gov.di.ipv.core.library.domain.VerifiableCredential;
import uk.gov.di.ipv.core.library.enums.Vot;
import uk.gov.di.ipv.core.library.evcs.service.EvcsService;
import uk.gov.di.ipv.core.library.exceptions.CredentialParseException;
import uk.gov.di.ipv.core.library.exceptions.HttpResponseExceptionWithErrorBody;
import uk.gov.di.ipv.core.library.gpg45.Gpg45ProfileEvaluator;
import uk.gov.di.ipv.core.library.persistence.item.ClientOAuthSessionItem;
import uk.gov.di.ipv.core.library.service.AuditService;
import uk.gov.di.ipv.core.library.service.CimitUtilityService;
import uk.gov.di.ipv.core.library.service.ConfigService;
import uk.gov.di.ipv.core.library.sis.audit.AuditExtensionsSisComparison;
import uk.gov.di.ipv.core.library.sis.audit.AuditRestrictedSisComparison;
import uk.gov.di.ipv.core.library.sis.client.SisClient;
import uk.gov.di.ipv.core.library.sis.client.SisGetStoredIdentityResult;
import uk.gov.di.ipv.core.library.sis.dto.SisStoredIdentityCheckDto;
import uk.gov.di.ipv.core.library.sis.enums.FailureCode;
import uk.gov.di.ipv.core.library.sis.enums.VerificationOutcome;
import uk.gov.di.ipv.core.library.useridentity.service.UserIdentityService;
import uk.gov.di.ipv.core.library.useridentity.service.VotMatcher;

import java.text.ParseException;
import java.util.List;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.mockito.ArgumentCaptor.forClass;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.lenient;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;
import static uk.gov.di.ipv.core.library.evcs.enums.EvcsVCState.CURRENT;
import static uk.gov.di.ipv.core.library.evcs.enums.EvcsVCState.PENDING_RETURN;

@ExtendWith(MockitoExtension.class)
class SisServiceTest {

    private static final String TEST_USER_ID = "test-user-id";
    private static final String TEST_TOKEN = "test-token";
    private static final String TEST_SESSION_ID = "test-session-id";
    private static final String TEST_GOV_SIGNIN_JOURNEY_ID = "test-gov-signin-journey-id";
    private static final String TEST_IP_ADDRESS = "test-ip-address";
    public static final List<Vot> REQUEST_VTR = List.of(Vot.P1, Vot.P2);

    @Mock private SisClient sisClient;
    @Mock private ConfigService configService;
    @Mock private AuditService auditService;
    @Mock private CimitUtilityService cimitUtilityService;
    @Mock private UserIdentityService userIdentityService;
    @Mock private EvcsService evcsService;
    @Mock private CriResponseService criResponseService;

    private ClientOAuthSessionItem clientOAuthSessionItem;
    private AuditEventUser auditEventUser;
    private SisService sisService;

    @BeforeEach
    void setUp() throws HttpResponseExceptionWithErrorBody {
        VotMatcher votMatcher =
                new VotMatcher(
                        userIdentityService, new Gpg45ProfileEvaluator(), cimitUtilityService);

        sisService =
                new SisService(
                        sisClient,
                        configService,
                        auditService,
                        cimitUtilityService,
                        userIdentityService,
                        votMatcher,
                        evcsService,
                        criResponseService);

        clientOAuthSessionItem = new ClientOAuthSessionItem();
        clientOAuthSessionItem.setUserId(TEST_USER_ID);
        clientOAuthSessionItem.setEvcsAccessToken(TEST_TOKEN);
        clientOAuthSessionItem.setGovukSigninJourneyId(TEST_GOV_SIGNIN_JOURNEY_ID);
        clientOAuthSessionItem.setVtr(REQUEST_VTR.stream().map(Enum::toString).toList());

        auditEventUser =
                new AuditEventUser(
                        TEST_USER_ID, TEST_SESSION_ID, TEST_GOV_SIGNIN_JOURNEY_ID, TEST_IP_ADDRESS);

        lenient().when(userIdentityService.areVcsCorrelated(any())).thenReturn(true);
    }

    @Test
    void shouldNotSendAuditEventWhenNoVcsAndNoSisResponse() throws Exception {
        // Arrange
        SisGetStoredIdentityResult sisResult = new SisGetStoredIdentityResult(true, false, null);

        when(sisClient.getStoredIdentity(TEST_TOKEN, REQUEST_VTR, TEST_GOV_SIGNIN_JOURNEY_ID))
                .thenReturn(sisResult);

        // Act
        sisService.compareStoredIdentityWithStoredVcs(clientOAuthSessionItem, auditEventUser);

        // Assert
        verify(auditService, never()).sendAuditEvent(any());
    }

    @Test
    void shouldSendFailureAuditEventWhenSisFails() throws Exception {
        // Arrange
        SisGetStoredIdentityResult sisFailureResult =
                new SisGetStoredIdentityResult(false, false, null);

        when(sisClient.getStoredIdentity(TEST_TOKEN, REQUEST_VTR, TEST_GOV_SIGNIN_JOURNEY_ID))
                .thenReturn(sisFailureResult);

        // Act
        sisService.compareStoredIdentityWithStoredVcs(clientOAuthSessionItem, auditEventUser);

        // Assert
        ArgumentCaptor<AuditEvent> auditEventCaptor = forClass(AuditEvent.class);
        verify(auditService, times(1)).sendAuditEvent(auditEventCaptor.capture());
        checkAuditEvent(
                auditEventCaptor.getValue(),
                VerificationOutcome.FAILURE,
                FailureCode.SIS_ERROR,
                null,
                null,
                null,
                "",
                List.of(),
                List.of(),
                "Call to SIS service failed, no stored identity comparison can be made");
    }

    @Test
    void shouldSendFailureAuditEventWhenEvcsFails() throws Exception {
        // Arrange

        when(sisClient.getStoredIdentity(TEST_TOKEN, REQUEST_VTR, TEST_GOV_SIGNIN_JOURNEY_ID))
                .thenReturn(SIS_SUCCESSFUL_RESULT);
        when(evcsService.fetchEvcsVerifiableCredentialsByState(
                        TEST_USER_ID, TEST_TOKEN, true, CURRENT, PENDING_RETURN))
                .thenThrow(new CredentialParseException("test exception"));

        // Act
        sisService.compareStoredIdentityWithStoredVcs(clientOAuthSessionItem, auditEventUser);

        // Assert
        ArgumentCaptor<AuditEvent> auditEventCaptor = forClass(AuditEvent.class);
        verify(auditService, times(1)).sendAuditEvent(auditEventCaptor.capture());
        checkAuditEvent(
                auditEventCaptor.getValue(),
                VerificationOutcome.FAILURE,
                FailureCode.EVCS_ERROR,
                false,
                true,
                Vot.P2,
                SIS_JWT,
                SUCCESSFUL_SIGNATURES,
                List.of(),
                "Exception caught retrieving VCs from EVCS");
    }

    @Test
    void shouldSendFailureAuditEventWhenVotCalculationFails() throws Exception {
        // Arrange

        when(sisClient.getStoredIdentity(TEST_TOKEN, REQUEST_VTR, TEST_GOV_SIGNIN_JOURNEY_ID))
                .thenReturn(SIS_SUCCESSFUL_RESULT);
        when(evcsService.fetchEvcsVerifiableCredentialsByState(
                        TEST_USER_ID, TEST_TOKEN, true, CURRENT, PENDING_RETURN))
                .thenReturn(Map.of(CURRENT, EVCS_SUCCESSFUL_VCS, PENDING_RETURN, List.of()));

        when(cimitUtilityService.getContraIndicatorsFromVc(any(), any()))
                .thenThrow(new CredentialParseException("test exception"));

        // Act
        sisService.compareStoredIdentityWithStoredVcs(clientOAuthSessionItem, auditEventUser);

        // Assert
        ArgumentCaptor<AuditEvent> auditEventCaptor = forClass(AuditEvent.class);
        verify(auditService, times(1)).sendAuditEvent(auditEventCaptor.capture());
        checkAuditEvent(
                auditEventCaptor.getValue(),
                VerificationOutcome.FAILURE,
                FailureCode.EVCS_VOT_CALCULATION_ERROR,
                false,
                true,
                Vot.P2,
                SIS_JWT,
                SUCCESSFUL_SIGNATURES,
                SUCCESSFUL_SIGNATURES,
                "Exception caught calculating VOT from EVCS VCs");
    }

    @Test
    void shouldSendFailureAuditEventWhenMaxVotComparisonFails() throws Exception {
        // Arrange
        var sisP2MaxResult =
                new SisGetStoredIdentityResult(
                        true,
                        true,
                        new SisStoredIdentityCheckDto(SIS_JWT, true, false, Vot.P2, true, true));

        when(sisClient.getStoredIdentity(TEST_TOKEN, REQUEST_VTR, TEST_GOV_SIGNIN_JOURNEY_ID))
                .thenReturn(sisP2MaxResult);
        when(evcsService.fetchEvcsVerifiableCredentialsByState(
                        TEST_USER_ID, TEST_TOKEN, true, CURRENT, PENDING_RETURN))
                .thenReturn(Map.of(CURRENT, EVCS_SUCCESSFUL_VCS, PENDING_RETURN, List.of()));

        // Act
        sisService.compareStoredIdentityWithStoredVcs(clientOAuthSessionItem, auditEventUser);

        // Assert
        ArgumentCaptor<AuditEvent> auditEventCaptor = forClass(AuditEvent.class);
        verify(auditService, times(1)).sendAuditEvent(auditEventCaptor.capture());
        checkAuditEvent(
                auditEventCaptor.getValue(),
                VerificationOutcome.FAILURE,
                FailureCode.MAX_VOT_MISMATCH,
                false,
                true,
                Vot.P2,
                SIS_JWT,
                SUCCESSFUL_SIGNATURES,
                SUCCESSFUL_SIGNATURES,
                "Maximum EVCS (P3) and SIS (P2) vots do not match");
    }

    @Test
    void shouldSendFailureAuditEventWhenRequestedVotComparisonFails() throws Exception {
        // Arrange
        var sisP1CalculatedResult =
                new SisGetStoredIdentityResult(
                        true,
                        true,
                        new SisStoredIdentityCheckDto(SIS_JWT_P1, true, false, Vot.P3, true, true));

        when(sisClient.getStoredIdentity(TEST_TOKEN, REQUEST_VTR, TEST_GOV_SIGNIN_JOURNEY_ID))
                .thenReturn(sisP1CalculatedResult);
        when(evcsService.fetchEvcsVerifiableCredentialsByState(
                        TEST_USER_ID, TEST_TOKEN, true, CURRENT, PENDING_RETURN))
                .thenReturn(Map.of(CURRENT, EVCS_SUCCESSFUL_VCS, PENDING_RETURN, List.of()));

        // Act
        sisService.compareStoredIdentityWithStoredVcs(clientOAuthSessionItem, auditEventUser);

        // Assert
        ArgumentCaptor<AuditEvent> auditEventCaptor = forClass(AuditEvent.class);
        verify(auditService, times(1)).sendAuditEvent(auditEventCaptor.capture());
        checkAuditEvent(
                auditEventCaptor.getValue(),
                VerificationOutcome.FAILURE,
                FailureCode.REQUESTED_VOT_MISMATCH,
                false,
                true,
                Vot.P1,
                SIS_JWT_P1,
                SUCCESSFUL_SIGNATURES,
                SUCCESSFUL_SIGNATURES,
                "Requested EVCS (P2) and SIS (P1) vots do not match");
    }

    @Test
    void shouldSendFailureAuditEventWhenSisHasAnExtraVc() throws Exception {
        // Arrange
        var sisP2Result =
                new SisGetStoredIdentityResult(
                        true,
                        true,
                        new SisStoredIdentityCheckDto(SIS_JWT, true, false, Vot.P3, true, true));

        when(sisClient.getStoredIdentity(TEST_TOKEN, REQUEST_VTR, TEST_GOV_SIGNIN_JOURNEY_ID))
                .thenReturn(sisP2Result);
        when(evcsService.fetchEvcsVerifiableCredentialsByState(
                        TEST_USER_ID, TEST_TOKEN, true, CURRENT, PENDING_RETURN))
                .thenReturn(Map.of(CURRENT, EVCS_MISSING_ONE_VCS, PENDING_RETURN, List.of()));

        // Act
        sisService.compareStoredIdentityWithStoredVcs(clientOAuthSessionItem, auditEventUser);

        // Assert
        ArgumentCaptor<AuditEvent> auditEventCaptor = forClass(AuditEvent.class);
        verify(auditService, times(1)).sendAuditEvent(auditEventCaptor.capture());
        checkAuditEvent(
                auditEventCaptor.getValue(),
                VerificationOutcome.FAILURE,
                FailureCode.EXTRA_SIGNATURE,
                false,
                true,
                Vot.P2,
                SIS_JWT,
                SUCCESSFUL_SIGNATURES,
                MISSING_ONE_SIGNATURES,
                "Some signatures in the stored identity are not present in EVCS: 71rsp9h4OS8kZOK4LtKh5dRtQ1uX8On4OL0W3nhCSmSZhtPJrE-0TXuc9rpzWzS0a92mc-aNGggcKDGp7oSc3g");
    }

    @Test
    void shouldSendFailureAuditEventWhenSisIsMissingAVc() throws Exception {
        // Arrange
        var sisP2Result =
                new SisGetStoredIdentityResult(
                        true,
                        true,
                        new SisStoredIdentityCheckDto(SIS_JWT, true, false, Vot.P3, true, true));

        when(sisClient.getStoredIdentity(TEST_TOKEN, REQUEST_VTR, TEST_GOV_SIGNIN_JOURNEY_ID))
                .thenReturn(sisP2Result);
        when(evcsService.fetchEvcsVerifiableCredentialsByState(
                        TEST_USER_ID, TEST_TOKEN, true, CURRENT, PENDING_RETURN))
                .thenReturn(Map.of(CURRENT, EVCS_EXTRA_ONE_VCS, PENDING_RETURN, List.of()));

        // Act
        sisService.compareStoredIdentityWithStoredVcs(clientOAuthSessionItem, auditEventUser);

        // Assert
        ArgumentCaptor<AuditEvent> auditEventCaptor = forClass(AuditEvent.class);
        verify(auditService, times(1)).sendAuditEvent(auditEventCaptor.capture());
        checkAuditEvent(
                auditEventCaptor.getValue(),
                VerificationOutcome.FAILURE,
                FailureCode.MISSING_SIGNATURE,
                false,
                true,
                Vot.P2,
                SIS_JWT,
                SUCCESSFUL_SIGNATURES,
                EXTRA_ONE_SIGNATURES,
                "Some signatures from EVCS are not in the stored identity: baWWfh_BWaZa_cvtf04vKnk0GxNZQx7OeY-HJzMorR9CIJMPMjDVZLjiX1JPZAvnEQCdz2w7SFcwNCGdOZLkwA");
    }

    @Test
    void shouldSendFailureAuditEventWhenUnexpectedErrorOccurs() throws Exception {
        // Arrange
        var sisP2Result =
                new SisGetStoredIdentityResult(
                        true,
                        true,
                        new SisStoredIdentityCheckDto(
                                "Not a valid JWT", true, false, Vot.P3, true, true));

        when(sisClient.getStoredIdentity(TEST_TOKEN, REQUEST_VTR, TEST_GOV_SIGNIN_JOURNEY_ID))
                .thenReturn(sisP2Result);

        // Act
        sisService.compareStoredIdentityWithStoredVcs(clientOAuthSessionItem, auditEventUser);

        // Assert
        ArgumentCaptor<AuditEvent> auditEventCaptor = forClass(AuditEvent.class);
        verify(auditService, times(1)).sendAuditEvent(auditEventCaptor.capture());
        checkAuditEvent(
                auditEventCaptor.getValue(),
                VerificationOutcome.FAILURE,
                FailureCode.UNEXPECTED_ERROR,
                false,
                true,
                null,
                "Not a valid JWT",
                List.of(),
                List.of(),
                "Index 1 out of bounds for length 1");
    }

    @Test
    void shouldSendSuccessAuditEventWhenEverythingMatches() throws Exception {
        // Arrange
        ArgumentCaptor<AuditEvent> auditEventCaptor = forClass(AuditEvent.class);

        when(sisClient.getStoredIdentity(TEST_TOKEN, REQUEST_VTR, TEST_GOV_SIGNIN_JOURNEY_ID))
                .thenReturn(SIS_SUCCESSFUL_RESULT);
        when(evcsService.fetchEvcsVerifiableCredentialsByState(
                        TEST_USER_ID, TEST_TOKEN, true, CURRENT, PENDING_RETURN))
                .thenReturn(Map.of(CURRENT, EVCS_SUCCESSFUL_VCS, PENDING_RETURN, List.of()));

        // Act
        sisService.compareStoredIdentityWithStoredVcs(clientOAuthSessionItem, auditEventUser);

        // Assert
        verify(auditService, times(1)).sendAuditEvent(auditEventCaptor.capture());
        checkAuditEvent(
                auditEventCaptor.getValue(),
                VerificationOutcome.SUCCESS,
                null,
                false,
                true,
                Vot.P2,
                SIS_JWT,
                SUCCESSFUL_SIGNATURES,
                SUCCESSFUL_SIGNATURES,
                null);
    }

    private void checkAuditEvent(
            AuditEvent auditEvent,
            VerificationOutcome expectedVerificationOutcome,
            FailureCode expectedFailureCode,
            Boolean expectedExpired,
            Boolean expectedIsValid,
            Vot expectedSisVot,
            String expectedSisJwt,
            List<String> expectedSisSignatures,
            List<String> expectedEvcsSignatures,
            String expectedFailureDetails) {
        var restrictedValues = (AuditRestrictedSisComparison) auditEvent.getRestricted();
        assertEquals(expectedFailureDetails, restrictedValues.getFailureDetails());
        assertEquals(expectedSisJwt, restrictedValues.getSisJwt());
        assertEquals(expectedSisSignatures, restrictedValues.getSisSignatures());
        assertEquals(expectedEvcsSignatures, restrictedValues.getReconstructedSignatures());

        var extensionValues = (AuditExtensionsSisComparison) auditEvent.getExtensions();
        assertEquals(expectedVerificationOutcome, extensionValues.getOutcome());
        assertEquals(expectedFailureCode, extensionValues.getFailureCode());
        assertEquals(expectedExpired, extensionValues.getExpired());
        assertEquals(expectedIsValid, extensionValues.getIsValid());
        assertEquals(expectedSisVot, extensionValues.getSisVot());
    }

    private static String getSignature(String jwt) {
        return jwt.split("\\.")[2];
    }

    private static VerifiableCredential createVc(String userId, Cri cri, String jwt)
            throws ParseException, CredentialParseException {
        return VerifiableCredential.fromValidJwt(userId, cri, SignedJWT.parse(jwt));
    }

    // Dummy JWTs containing realistic looking data, created using JWT.IO and the dummy JWT content
    // from process-cri-callback contract tests
    private static final String DCMAW_PASSPORT_JWT =
            // pragma: allowlist nextline secret
            "eyJhbGciOiJFUzI1NiIsInR5cCI6IkpXVCJ9.eyJpYXQiOjE3MTIyMjg3MjgsImlzcyI6ImR1bW15RGNtYXdDb21wb25lbnRJZCIsImF1ZCI6Imlzc3VlciIsInN1YiI6InRlc3Qtc3ViamVjdCIsIm5iZiI6NDA3MDkwODgwMCwianRpIjoidXJuOnV1aWQ6YzViN2MxYjAtODI2Mi00ZDU3LWIxNjgtOWJjOTQ1NjhhZjE3IiwidmMiOnsiQGNvbnRleHQiOlsiaHR0cHM6Ly93d3cudzMub3JnLzIwMTgvY3JlZGVudGlhbHMvdjEiLCJodHRwczovL3ZvY2FiLmFjY291bnQuZ292LnVrL2NvbnRleHRzL2lkZW50aXR5LXYxLmpzb25sZCJdLCJ0eXBlIjpbIlZlcmlmaWFibGVDcmVkZW50aWFsIiwiSWRlbnRpdHlDaGVja0NyZWRlbnRpYWwiXSwiY3JlZGVudGlhbFN1YmplY3QiOnsibmFtZSI6W3sibmFtZVBhcnRzIjpbeyJ0eXBlIjoiR2l2ZW5OYW1lIiwidmFsdWUiOiJBTk5BIn0seyJ0eXBlIjoiR2l2ZW5OYW1lIiwidmFsdWUiOiJOSUNIT0xBIn0seyJ0eXBlIjoiRmFtaWx5TmFtZSIsInZhbHVlIjoiT1RIRVIgRk9SVFlGT1VSIn1dfV0sImJpcnRoRGF0ZSI6W3sidmFsdWUiOiIxOTYwLTAxLTAxIn1dLCJkZXZpY2VJZCI6W3sidmFsdWUiOiJhMzAxNzUxMS1iNjM5LTQ2ZmYtYWI3My02NmU1YWIwMTkzYzkifV0sInBhc3Nwb3J0IjpbeyJkb2N1bWVudE51bWJlciI6IjU0OTM2NDc4MyIsImV4cGlyeURhdGUiOiIyMDI3LTA4LTAxIiwiaWNhb0lzc3VlckNvZGUiOiJHQlIifV19LCJldmlkZW5jZSI6W3sidHlwZSI6IklkZW50aXR5Q2hlY2siLCJ0eG4iOiJiaW9tZXRyaWNJZCIsInN0cmVuZ3RoU2NvcmUiOjQsInZhbGlkaXR5U2NvcmUiOjMsImNoZWNrRGV0YWlscyI6W3siY2hlY2tNZXRob2QiOiJ2Y3J5cHQiLCJpZGVudGl0eUNoZWNrUG9saWN5IjoicHVibGlzaGVkIiwiYWN0aXZpdHlGcm9tIjpudWxsfSx7ImNoZWNrTWV0aG9kIjoiYnZyIiwiYmlvbWV0cmljVmVyaWZpY2F0aW9uUHJvY2Vzc0xldmVsIjozfV19XX0sImV4cCI6NDA3MDkwOTQwMH0.Zm5QyGSgLY9neAGMA7hza-uR7Ekiz1onSU8s0iz2wPXlrBLTjnUKQNMWnIpJeY4IMEHNvL0zJpvdykJgAb6Qew";
    private static final String ADDRESS_JWT =
            // pragma: allowlist nextline secret
            "eyJ0eXAiOiJKV1QiLCJhbGciOiJFUzI1NiIsImtpZCI6ImRpZDp3ZWI6ZHVtbXlBZGRyZXNzQ29tcG9uZW50SWQjMTc1M2NmMGIxZTM2NDdkOTE3MTk4MjBiNzRjZjBjNGYwODc4MmQwZjA3MmViYWY1ZWM0ZWUwODczNDM2YTdhYiJ9.eyJpc3MiOiJkdW1teUFkZHJlc3NDb21wb25lbnRJZCIsInN1YiI6InRlc3Qtc3ViamVjdCIsIm5iZiI6NDA3MDkwODgwMCwiZXhwIjo0MDcwOTA5NDAwLCJ2YyI6eyJ0eXBlIjpbIlZlcmlmaWFibGVDcmVkZW50aWFsIiwiQWRkcmVzc0NyZWRlbnRpYWwiXSwiQGNvbnRleHQiOlsiaHR0cHM6Ly93d3cudzMub3JnLzIwMTgvY3JlZGVudGlhbHMvdjEiLCJodHRwczovL3ZvY2FiLmFjY291bnQuZ292LnVrL2NvbnRleHRzL2lkZW50aXR5LXYxLmpzb25sZCJdLCJjcmVkZW50aWFsU3ViamVjdCI6eyJhZGRyZXNzIjpbeyJhZGRyZXNzQ291bnRyeSI6IkdCIiwiYnVpbGRpbmdOYW1lIjoiIiwic3RyZWV0TmFtZSI6IkhBRExFWSBST0FEIiwicG9zdGFsQ29kZSI6IkJBMiA1QUEiLCJidWlsZGluZ051bWJlciI6IjgiLCJhZGRyZXNzTG9jYWxpdHkiOiJCQVRIIiwidmFsaWRGcm9tIjoiMjAwMC0wMS0wMSJ9XX19LCJqdGkiOiJkdW1teUp0aSJ9.71rsp9h4OS8kZOK4LtKh5dRtQ1uX8On4OL0W3nhCSmSZhtPJrE-0TXuc9rpzWzS0a92mc-aNGggcKDGp7oSc3g";
    private static final String FRAUD_JWT =
            // pragma: allowlist nextline secret
            "eyJ0eXAiOiJKV1QiLCJhbGciOiJFUzI1NiJ9.eyJpc3MiOiJkdW1teUZyYXVkQ29tcG9uZW50SWQiLCJzdWIiOiJ0ZXN0LXN1YmplY3QiLCJuYmYiOjQwNzA5MDg4MDAsInZjIjp7InR5cGUiOlsiVmVyaWZpYWJsZUNyZWRlbnRpYWwiLCJJZGVudGl0eUNoZWNrQ3JlZGVudGlhbCJdLCJjcmVkZW50aWFsU3ViamVjdCI6eyJhZGRyZXNzIjpbeyJidWlsZGluZ051bWJlciI6IjgiLCJidWlsZGluZ05hbWUiOiJMRSBGTEFNQkUiLCJzdHJlZXROYW1lIjoiSEFETEVZIFJPQUQiLCJhZGRyZXNzTG9jYWxpdHkiOiJCQVRIIiwicG9zdGFsQ29kZSI6IkJBMiA1QUEiLCJhZGRyZXNzQ291bnRyeSI6IkdCIn1dLCJiaXJ0aERhdGUiOlt7InZhbHVlIjoiMTk2NS0wNy0wOCJ9XSwibmFtZSI6W3sibmFtZVBhcnRzIjpbeyJ0eXBlIjoiR2l2ZW5OYW1lIiwidmFsdWUiOiJLZW5uZXRoIn0seyJ0eXBlIjoiRmFtaWx5TmFtZSIsInZhbHVlIjoiRGVjZXJxdWVpcmEifV19XX0sImV2aWRlbmNlIjpbeyJ0eXBlIjoiSWRlbnRpdHlDaGVjayIsInR4biI6ImR1bW15VHhuIiwiaWRlbnRpdHlGcmF1ZFNjb3JlIjoyLCJjaSI6W10sImFjdGl2aXR5SGlzdG9yeVNjb3JlIjoxLCJjaGVja0RldGFpbHMiOlt7ImNoZWNrTWV0aG9kIjoiZGF0YSIsImZyYXVkQ2hlY2siOiJhcHBsaWNhYmxlX2F1dGhvcml0YXRpdmVfc291cmNlIn0seyJjaGVja01ldGhvZCI6ImRhdGEiLCJmcmF1ZENoZWNrIjoiYXZhaWxhYmxlX2F1dGhvcml0YXRpdmVfc291cmNlIn0seyJjaGVja01ldGhvZCI6ImRhdGEiLCJmcmF1ZENoZWNrIjoibW9ydGFsaXR5X2NoZWNrIn0seyJjaGVja01ldGhvZCI6ImRhdGEiLCJmcmF1ZENoZWNrIjoiaWRlbnRpdHlfdGhlZnRfY2hlY2sifSx7ImNoZWNrTWV0aG9kIjoiZGF0YSIsImZyYXVkQ2hlY2siOiJzeW50aGV0aWNfaWRlbnRpdHlfY2hlY2sifSx7InR4biI6ImR1bW15VHhuIiwiY2hlY2tNZXRob2QiOiJkYXRhIiwiZnJhdWRDaGVjayI6ImltcGVyc29uYXRpb25fcmlza19jaGVjayJ9LHsiY2hlY2tNZXRob2QiOiJkYXRhIiwiYWN0aXZpdHlGcm9tIjoiMjAxMy0xMi0wMSIsImlkZW50aXR5Q2hlY2tQb2xpY3kiOiJub25lIn1dfV19LCJqdGkiOiJ1cm46dXVpZDpiMDdjYzdlMy1hMmRjLTRiMTctOTgyNi02OTA3ZmNmNDA1OWEifQ.LKmv31LwPWEKWuiTUuhVrm367-SXFffLNLMg15er8t3Iptny-Oy1pHE-TMd80W-7DgVEI1oBW1CFM8wUwvUI8g";
    private static final String CIC_JWT =
            // pragma: allowlist nextline secret
            "eyJ0eXAiOiJKV1QiLCJhbGciOiJFUzI1NiJ9.eyJuYmYiOjQwNzA5MDg4MDAsImlhdCI6NDA3MDkwODgwMCwianRpIjoianRpIiwiaXNzIjoiaHR0cHM6Ly9yZXZpZXctYy5kZXYuYWNjb3VudC5nb3YudWsiLCJzdWIiOiJ0ZXN0LXN1YmplY3QiLCJ2YyI6eyJAY29udGV4dCI6WyJodHRwczovL3d3dy53My5vcmcvMjAxOC9jcmVkZW50aWFscy92MSIsImh0dHBzOi8vdm9jYWIuYWNjb3VudC5nb3YudWsvY29udGV4dHMvaWRlbnRpdHktdjEuanNvbmxkIl0sInR5cGUiOlsiVmVyaWZpYWJsZUNyZWRlbnRpYWwiLCJJZGVudGl0eUFzc2VydGlvbkNyZWRlbnRpYWwiXSwiY3JlZGVudGlhbFN1YmplY3QiOnsibmFtZSI6W3sibmFtZVBhcnRzIjpbeyJ0eXBlIjoiR2l2ZW5OYW1lIiwidmFsdWUiOiJNYXJ5In0seyJ0eXBlIjoiRmFtaWx5TmFtZSIsInZhbHVlIjoiV2F0c29uIn1dfV0sImJpcnRoRGF0ZSI6W3sidmFsdWUiOiIxOTMyLTAyLTI1In1dfX19.baWWfh_BWaZa_cvtf04vKnk0GxNZQx7OeY-HJzMorR9CIJMPMjDVZLjiX1JPZAvnEQCdz2w7SFcwNCGdOZLkwA";
    // Generated using vcTicf().getVcString()
    private static final String CIMIT_JWT =
            // pragma: allowlist nextline secret
            "eyJ0eXAiOiJKV1QiLCJhbGciOiJFUzI1NiJ9.eyJpc3MiOiJodHRwczovL3RpY2Yuc3R1YnMuYWNjb3VudC5nb3YudWsiLCJzdWIiOiJ1cm46dXVpZDowMWE0NDM0Mi1lNjQzLTRjYTktODMwNi1hOGUwNDQwOTJmYjAiLCJuYmYiOjE3MDQ4MjI1NzAsImlhdCI6MTcwNDgyMjU3MCwidmMiOnsiZXZpZGVuY2UiOlt7InR4biI6Ijk2M2RlZWI1LWE1MmMtNDAzMC1hNjlhLTMxODRmNzdhNGYxOCIsInR5cGUiOiJSaXNrQXNzZXNzbWVudCJ9XSwidHlwZSI6WyJWZXJpZmlhYmxlQ3JlZGVudGlhbCIsIlJpc2tBc3Nlc3NtZW50Q3JlZGVudGlhbCJdfX0.H3mI9mnYfYRszuAQa-0HyIMkIjcmukvMsmpdOo0cTICOWwmvLF-hJgIqSkK17m2Ua6PE3wNo0CiLsotVK84_Og";

    // Created in JWT.IO to contain the signatures from DCMAW_PASSPORT_JWT, ADDRESS_JWT, FRAUD_JWT,
    // and CIMIT_JWT. Claiming to match a P2
    private static final String SIS_JWT =
            // pragma: allowlist nextline secret
            "eyJraWQiOiJ0ZXN0LXNpZ25pbmcta2V5IiwidHlwIjoiSldUIiwiYWxnIjoiRVMyNTYifQ.eyJhdWQiOiJodHRwczovL3JldXNlLWlkZW50aXR5LmJ1aWxkLmFjY291bnQuZ292LnVrIiwic3ViIjoic2lzdGVzdCIsIm5iZiI6MTc1NjgwODMwNCwiY3JlZGVudGlhbHMiOlsiWm01UXlHU2dMWTluZUFHTUE3aHphLXVSN0VraXoxb25TVThzMGl6MndQWGxyQkxUam5VS1FOTVduSXBKZVk0SU1FSE52TDB6SnB2ZHlrSmdBYjZRZXciLCI3MXJzcDloNE9TOGtaT0s0THRLaDVkUnRRMXVYOE9uNE9MMFczbmhDU21TWmh0UEpyRS0wVFh1YzlycHpXelMwYTkybWMtYU5HZ2djS0RHcDdvU2MzZyIsIkxLbXYzMUx3UFdFS1d1aVRVdWhWcm0zNjctU1hGZmZMTkxNZzE1ZXI4dDNJcHRueS1PeTFwSEUtVE1kODBXLTdEZ1ZFSTFvQlcxQ0ZNOHdVd3ZVSThnIiwiSDNtSTltbllmWVJzenVBUWEtMEh5SU1rSWpjbXVrdk1zbXBkT28wY1RJQ09Xd212TEYtaEpnSXFTa0sxN20yVWE2UEUzd05vMENpTHNvdFZLODRfT2ciXSwiaXNzIjoiaHR0cHM6Ly9pZGVudGl0eS5sb2NhbC5hY2NvdW50Lmdvdi51ayIsImNsYWltcyI6eyJodHRwczovL3ZvY2FiLmFjY291bnQuZ292LnVrL3YxL2NvcmVJZGVudGl0eSI6eyJuYW1lIjpbeyJuYW1lUGFydHMiOlt7InR5cGUiOiJHaXZlbk5hbWUiLCJ2YWx1ZSI6Iktlbm5ldGgifSx7InR5cGUiOiJGYW1pbHlOYW1lIiwidmFsdWUiOiJEZWNlcnF1ZWlyYSJ9XX1dLCJiaXJ0aERhdGUiOlt7InZhbHVlIjoiMTk2NS0wNy0wOCJ9XX0sImh0dHBzOi8vdm9jYWIuYWNjb3VudC5nb3YudWsvdjEvYWRkcmVzcyI6W3siYWRkcmVzc0NvdW50cnkiOiJHQiIsImFkZHJlc3NMb2NhbGl0eSI6IkJBVEgiLCJidWlsZGluZ05hbWUiOiIiLCJidWlsZGluZ051bWJlciI6IjgiLCJwb3N0YWxDb2RlIjoiQkEyIDVBQSIsInN0cmVldE5hbWUiOiJIQURMRVkgUk9BRCIsInZhbGlkRnJvbSI6IjIwMDAtMDEtMDEifV0sImh0dHBzOi8vdm9jYWIuYWNjb3VudC5nb3YudWsvdjEvcGFzc3BvcnQiOlt7ImRvY3VtZW50TnVtYmVyIjoiMzIxNjU0OTg3IiwiZXhwaXJ5RGF0ZSI6IjIwMzAtMDEtMDEiLCJpY2FvSXNzdWVyQ29kZSI6IkdCUiJ9XX0sInZvdCI6IlAyIiwiaWF0IjoxNzU2ODA4MzA0fQ.40hzV7Uv7pquD-hd62-ABHIp6p0AwsUCmNosOjhMz2Ylx0q4OTNFyAZzsarVUz_AGgKVE6Zl67DIzg1lVacWUg";

    // This JWT is the same as the one above except that it says that the user has only reached P1
    // instead of P2 for this request
    private static final String SIS_JWT_P1 =
            // pragma: allowlist nextline secret
            "eyJraWQiOiJ0ZXN0LXNpZ25pbmcta2V5IiwidHlwIjoiSldUIiwiYWxnIjoiRVMyNTYifQ.eyJhdWQiOiJodHRwczovL3JldXNlLWlkZW50aXR5LmJ1aWxkLmFjY291bnQuZ292LnVrIiwic3ViIjoic2lzdGVzdCIsIm5iZiI6MTc1NjgwODMwNCwiY3JlZGVudGlhbHMiOlsiWm01UXlHU2dMWTluZUFHTUE3aHphLXVSN0VraXoxb25TVThzMGl6MndQWGxyQkxUam5VS1FOTVduSXBKZVk0SU1FSE52TDB6SnB2ZHlrSmdBYjZRZXciLCI3MXJzcDloNE9TOGtaT0s0THRLaDVkUnRRMXVYOE9uNE9MMFczbmhDU21TWmh0UEpyRS0wVFh1YzlycHpXelMwYTkybWMtYU5HZ2djS0RHcDdvU2MzZyIsIkxLbXYzMUx3UFdFS1d1aVRVdWhWcm0zNjctU1hGZmZMTkxNZzE1ZXI4dDNJcHRueS1PeTFwSEUtVE1kODBXLTdEZ1ZFSTFvQlcxQ0ZNOHdVd3ZVSThnIiwiSDNtSTltbllmWVJzenVBUWEtMEh5SU1rSWpjbXVrdk1zbXBkT28wY1RJQ09Xd212TEYtaEpnSXFTa0sxN20yVWE2UEUzd05vMENpTHNvdFZLODRfT2ciXSwiaXNzIjoiaHR0cHM6Ly9pZGVudGl0eS5sb2NhbC5hY2NvdW50Lmdvdi51ayIsImNsYWltcyI6eyJodHRwczovL3ZvY2FiLmFjY291bnQuZ292LnVrL3YxL2NvcmVJZGVudGl0eSI6eyJuYW1lIjpbeyJuYW1lUGFydHMiOlt7InR5cGUiOiJHaXZlbk5hbWUiLCJ2YWx1ZSI6Iktlbm5ldGgifSx7InR5cGUiOiJGYW1pbHlOYW1lIiwidmFsdWUiOiJEZWNlcnF1ZWlyYSJ9XX1dLCJiaXJ0aERhdGUiOlt7InZhbHVlIjoiMTk2NS0wNy0wOCJ9XX0sImh0dHBzOi8vdm9jYWIuYWNjb3VudC5nb3YudWsvdjEvYWRkcmVzcyI6W3siYWRkcmVzc0NvdW50cnkiOiJHQiIsImFkZHJlc3NMb2NhbGl0eSI6IkJBVEgiLCJidWlsZGluZ05hbWUiOiIiLCJidWlsZGluZ051bWJlciI6IjgiLCJwb3N0YWxDb2RlIjoiQkEyIDVBQSIsInN0cmVldE5hbWUiOiJIQURMRVkgUk9BRCIsInZhbGlkRnJvbSI6IjIwMDAtMDEtMDEifV0sImh0dHBzOi8vdm9jYWIuYWNjb3VudC5nb3YudWsvdjEvcGFzc3BvcnQiOlt7ImRvY3VtZW50TnVtYmVyIjoiMzIxNjU0OTg3IiwiZXhwaXJ5RGF0ZSI6IjIwMzAtMDEtMDEiLCJpY2FvSXNzdWVyQ29kZSI6IkdCUiJ9XX0sInZvdCI6IlAxIiwiaWF0IjoxNzU2ODA4MzA0fQ.7DvTrBqiQayu01nElk0udyDA_4PXq2HxIxC4gZOXwGbBLowElKi1sSOxrmIdQt5UbwHgGtr_MVe4bRvWWvbFWQ";

    private static final SisGetStoredIdentityResult SIS_SUCCESSFUL_RESULT =
            new SisGetStoredIdentityResult(
                    true,
                    true,
                    new SisStoredIdentityCheckDto(SIS_JWT, true, false, Vot.P3, true, true));

    private static final List<VerifiableCredential> EVCS_SUCCESSFUL_VCS;
    private static final List<VerifiableCredential> EVCS_MISSING_ONE_VCS;
    private static final List<VerifiableCredential> EVCS_EXTRA_ONE_VCS;

    static {
        try {
            EVCS_SUCCESSFUL_VCS =
                    List.of(
                            createVc("test_user", Cri.DCMAW, DCMAW_PASSPORT_JWT),
                            createVc("test_user", Cri.ADDRESS, ADDRESS_JWT),
                            createVc("test_user", Cri.EXPERIAN_FRAUD, FRAUD_JWT),
                            createVc("test_user", Cri.CIMIT, CIMIT_JWT));

            EVCS_MISSING_ONE_VCS =
                    List.of(
                            createVc("test_user", Cri.DCMAW, DCMAW_PASSPORT_JWT),
                            createVc("test_user", Cri.EXPERIAN_FRAUD, FRAUD_JWT),
                            createVc("test_user", Cri.CIMIT, CIMIT_JWT));

            EVCS_EXTRA_ONE_VCS =
                    List.of(
                            createVc("test_user", Cri.DCMAW, DCMAW_PASSPORT_JWT),
                            createVc("test_user", Cri.ADDRESS, ADDRESS_JWT),
                            createVc("test_user", Cri.EXPERIAN_FRAUD, FRAUD_JWT),
                            createVc("test_user", Cri.CIMIT, CIMIT_JWT),
                            createVc("test_user", Cri.CLAIMED_IDENTITY, CIC_JWT));
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
    }

    private static final List<String> SUCCESSFUL_SIGNATURES =
            List.of(
                    getSignature(DCMAW_PASSPORT_JWT),
                    getSignature(ADDRESS_JWT),
                    getSignature(FRAUD_JWT),
                    getSignature(CIMIT_JWT));

    private static final List<String> MISSING_ONE_SIGNATURES =
            List.of(
                    getSignature(DCMAW_PASSPORT_JWT),
                    getSignature(FRAUD_JWT),
                    getSignature(CIMIT_JWT));

    private static final List<String> EXTRA_ONE_SIGNATURES =
            List.of(
                    getSignature(DCMAW_PASSPORT_JWT),
                    getSignature(ADDRESS_JWT),
                    getSignature(FRAUD_JWT),
                    getSignature(CIMIT_JWT),
                    getSignature(CIC_JWT));
}
