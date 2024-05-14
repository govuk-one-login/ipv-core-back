package uk.gov.di.ipv.core.identitycontinuitycheck;

import com.amazonaws.services.lambda.runtime.Context;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.mockito.junit.jupiter.MockitoSettings;
import uk.gov.di.ipv.core.library.config.ConfigurationVariable;
import uk.gov.di.ipv.core.library.domain.BirthDate;
import uk.gov.di.ipv.core.library.domain.IdentityClaim;
import uk.gov.di.ipv.core.library.domain.Name;
import uk.gov.di.ipv.core.library.domain.NameParts;
import uk.gov.di.ipv.core.library.domain.ProcessRequest;
import uk.gov.di.ipv.core.library.domain.VerifiableCredential;
import uk.gov.di.ipv.core.library.exceptions.VerifiableCredentialException;
import uk.gov.di.ipv.core.library.persistence.item.ClientOAuthSessionItem;
import uk.gov.di.ipv.core.library.persistence.item.IpvSessionItem;
import uk.gov.di.ipv.core.library.service.ClientOAuthSessionDetailsService;
import uk.gov.di.ipv.core.library.service.ConfigService;
import uk.gov.di.ipv.core.library.service.IpvSessionService;
import uk.gov.di.ipv.core.library.service.UserIdentityService;
import uk.gov.di.ipv.core.library.verifiablecredential.service.SessionCredentialsService;
import uk.gov.di.ipv.core.library.verifiablecredential.service.VerifiableCredentialService;

import java.util.Arrays;
import java.util.List;
import java.util.Optional;

import static org.apache.http.HttpStatus.SC_BAD_REQUEST;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.when;
import static org.mockito.quality.Strictness.LENIENT;
import static uk.gov.di.ipv.core.library.domain.CoiSubJourneyTypes.FAMILY_NAME_ONLY;
import static uk.gov.di.ipv.core.library.domain.CoiSubJourneyTypes.GIVEN_NAMES_ONLY;
import static uk.gov.di.ipv.core.library.domain.ErrorResponse.FAILED_TO_GET_CREDENTIAL;
import static uk.gov.di.ipv.core.library.domain.ErrorResponse.MISSING_IPV_SESSION_ID;
import static uk.gov.di.ipv.core.library.enums.Vot.P2;
import static uk.gov.di.ipv.core.library.fixtures.VcFixtures.EXPIRED_M1A_EXPERIAN_FRAUD_VC;
import static uk.gov.di.ipv.core.library.fixtures.VcFixtures.M1A_ADDRESS_VC;
import static uk.gov.di.ipv.core.library.fixtures.VcFixtures.PASSPORT_NON_DCMAW_SUCCESSFUL_VC;
import static uk.gov.di.ipv.core.library.journeyuris.JourneyUris.JOURNEY_CONTINUING_IDENTITY_CHECK_PASS_PATH;
import static uk.gov.di.ipv.core.library.journeyuris.JourneyUris.JOURNEY_ERROR_PATH;
import static uk.gov.di.ipv.core.library.service.UserIdentityService.FAMILY_NAME_PROPERTY_NAME;
import static uk.gov.di.ipv.core.library.service.UserIdentityService.GIVEN_NAME_PROPERTY_NAME;

@ExtendWith(MockitoExtension.class)
class IdentityContinuityCheckHandlerTest {

    private static final String CLIENT_SESSION_ID = "client-session-id";
    private static final String CODE = "code";
    private static final String JOURNEY = "journey";
    private static final String GOVUK_JOURNEY_ID = "govuk-journey-id";
    private static final String USER_ID = "user-id";
    private static ClientOAuthSessionItem clientOAuthSessionItem;
    private static IpvSessionItem ipvSessionItem;
    private static final String SESSION_ID = "session-id";
    private static final String COMPONENT_ID = "https://component-id.example";
    private static final String STATUS_CODE = "statusCode";
    private static final String MESSAGE = "message";
    private static final List<VerifiableCredential> VCS =
            List.of(
                    PASSPORT_NON_DCMAW_SUCCESSFUL_VC,
                    EXPIRED_M1A_EXPERIAN_FRAUD_VC,
                    M1A_ADDRESS_VC);
    private static final ProcessRequest PROCESS_REQUEST =
            ProcessRequest.processRequestBuilder()
                    .ipvSessionId(SESSION_ID)
                    .ipAddress("1.2.3.4")
                    .build();

    private static final IdentityClaim IDENTITY_CLAIM_1 =
            new IdentityClaim(
                    Arrays.asList(
                            new Name(List.of(new NameParts("FirstName", GIVEN_NAME_PROPERTY_NAME))),
                            new Name(
                                    List.of(
                                            new NameParts(
                                                    "SecondName", FAMILY_NAME_PROPERTY_NAME)))),
                    List.of(new BirthDate()));
    private static final IdentityClaim IDENTITY_CLAIM_2 =
            new IdentityClaim(
                    Arrays.asList(
                            new Name(
                                    List.of(
                                            new NameParts(
                                                    "New-FirstName", GIVEN_NAME_PROPERTY_NAME))),
                            new Name(
                                    List.of(
                                            new NameParts(
                                                    "New-SecondName", FAMILY_NAME_PROPERTY_NAME)))),
                    List.of(new BirthDate()));
    private static final IdentityClaim IDENTITY_CLAIM_3 =
            new IdentityClaim(
                    Arrays.asList(
                            new Name(List.of(new NameParts("FirstName", GIVEN_NAME_PROPERTY_NAME))),
                            new Name(
                                    List.of(
                                            new NameParts(
                                                    "SecondName", FAMILY_NAME_PROPERTY_NAME)))),
                    List.of(new BirthDate("2000-01-01")));

    @Mock private Context mockContext;
    @Mock private ConfigService mockConfigService;
    @Mock private IpvSessionService mockIpvSessionService;
    @Mock private ClientOAuthSessionDetailsService mockClientOauthSessionDetailsService;
    @Mock private SessionCredentialsService mockSessionCredentialService;
    @Mock private VerifiableCredentialService mockVerifiableCredentialService;
    @Mock private UserIdentityService mockUserIdentityService;

    @InjectMocks private IdentityContinuityCheckHandler identityContinuityCheckHandler;

    @BeforeAll
    static void setUpBeforeAll() {
        clientOAuthSessionItem = new ClientOAuthSessionItem();
        clientOAuthSessionItem.setUserId(USER_ID);
        clientOAuthSessionItem.setGovukSigninJourneyId(GOVUK_JOURNEY_ID);
    }

//    @BeforeEach
//    void setUpBeforeEach() throws Exception {
//
//        when(mockClientOauthSessionDetailsService.getClientOAuthSession(CLIENT_SESSION_ID))
//                .thenReturn(clientOAuthSessionItem);
//        when(mockSessionCredentialService.getCredentials(SESSION_ID, USER_ID)).thenReturn(VCS);
//        when(mockVerifiableCredentialService.getVcs(USER_ID)).thenReturn(VCS);
//        when(mockConfigService.getSsmParameter(ConfigurationVariable.COMPONENT_ID))
//                .thenReturn(COMPONENT_ID);
//    }

    @Test
    void shouldReturnErrorJourneyIfIpvSessionIdMissing() throws Exception {

        var processRequestWithMissingSessionId = ProcessRequest.processRequestBuilder().build();

        var response =
                identityContinuityCheckHandler.handleRequest(
                        processRequestWithMissingSessionId, mockContext);

        assertEquals(JOURNEY_ERROR_PATH, response.get(JOURNEY));
        assertEquals(SC_BAD_REQUEST, response.get(STATUS_CODE));
        assertEquals(MISSING_IPV_SESSION_ID.getCode(), response.get(CODE));
        assertEquals(MISSING_IPV_SESSION_ID.getMessage(), response.get(MESSAGE));
    }

    @Test
    void shouldReturnErrorJourneyIfCantFetchSessionCredentials() throws Exception {
        ipvSessionItem = new IpvSessionItem();
        ipvSessionItem.setIpvSessionId(SESSION_ID);
        ipvSessionItem.setClientOAuthSessionId(CLIENT_SESSION_ID);

        when(mockIpvSessionService.getIpvSession(SESSION_ID)).thenReturn(ipvSessionItem);
        when(mockClientOauthSessionDetailsService.getClientOAuthSession(CLIENT_SESSION_ID))
                .thenReturn(clientOAuthSessionItem);
        when(mockConfigService.getSsmParameter(ConfigurationVariable.COMPONENT_ID))
                .thenReturn(COMPONENT_ID);
        when(mockSessionCredentialService.getCredentials(SESSION_ID, USER_ID))
                .thenThrow(new VerifiableCredentialException(418, FAILED_TO_GET_CREDENTIAL));

        var response = identityContinuityCheckHandler.handleRequest(PROCESS_REQUEST, mockContext);

        assertEquals(JOURNEY_ERROR_PATH, response.get(JOURNEY));
        assertEquals(418, response.get(STATUS_CODE));
        assertEquals(FAILED_TO_GET_CREDENTIAL.getCode(), response.get(CODE));
        assertEquals(FAILED_TO_GET_CREDENTIAL.getMessage(), response.get(MESSAGE));
    }

    @Test
    void shouldReturnJourneyContinuingIdentityCheckPassIfIdentityContinuityMatchGivenName()
            throws Exception {
        ipvSessionItem = new IpvSessionItem();
        ipvSessionItem.setIpvSessionId(SESSION_ID);
        ipvSessionItem.setClientOAuthSessionId(CLIENT_SESSION_ID);
        ipvSessionItem.setCoiSubJourneyType(GIVEN_NAMES_ONLY);
        when(mockIpvSessionService.getIpvSession(SESSION_ID)).thenReturn(ipvSessionItem);
        when(mockClientOauthSessionDetailsService.getClientOAuthSession(CLIENT_SESSION_ID))
                .thenReturn(clientOAuthSessionItem);
        when(mockSessionCredentialService.getCredentials(SESSION_ID, USER_ID)).thenReturn(VCS);
        when(mockVerifiableCredentialService.getVcs(USER_ID)).thenReturn(VCS);
        when(mockConfigService.getSsmParameter(ConfigurationVariable.COMPONENT_ID))
                .thenReturn(COMPONENT_ID);
        when(mockUserIdentityService.findIdentityClaim(VCS))
                .thenReturn(Optional.of(IDENTITY_CLAIM_1));
        when(mockUserIdentityService.findIdentityClaim(VCS))
                .thenReturn(Optional.of(IDENTITY_CLAIM_1));
        when(mockUserIdentityService.getNormalizedName(any(), any()))
                .thenReturn("FirstName")
                .thenReturn("FirstName");

        var response = identityContinuityCheckHandler.handleRequest(PROCESS_REQUEST, mockContext);

        assertEquals(JOURNEY_CONTINUING_IDENTITY_CHECK_PASS_PATH, response.get(JOURNEY));
    }

    @Test
    void shouldReturnErrorJourneyIfIdentityContinuityCheckFailsIdentityContinuityMatchGivenName()
            throws Exception {
        ipvSessionItem = new IpvSessionItem();
        ipvSessionItem.setIpvSessionId(SESSION_ID);
        ipvSessionItem.setClientOAuthSessionId(CLIENT_SESSION_ID);
        ipvSessionItem.setCoiSubJourneyType(FAMILY_NAME_ONLY);
        when(mockIpvSessionService.getIpvSession(SESSION_ID)).thenReturn(ipvSessionItem);
        when(mockClientOauthSessionDetailsService.getClientOAuthSession(CLIENT_SESSION_ID))
                .thenReturn(clientOAuthSessionItem);
        when(mockSessionCredentialService.getCredentials(SESSION_ID, USER_ID)).thenReturn(VCS);
        when(mockVerifiableCredentialService.getVcs(USER_ID)).thenReturn(VCS);
        when(mockUserIdentityService.findIdentityClaim(VCS))
                .thenReturn(Optional.of(IDENTITY_CLAIM_1));
        when(mockUserIdentityService.findIdentityClaim(VCS))
                .thenReturn(Optional.of(IDENTITY_CLAIM_2));
        when(mockUserIdentityService.getNormalizedName(any(), any()))
                .thenReturn("FirstName")
                .thenReturn("New-FirstName");

        var response = identityContinuityCheckHandler.handleRequest(PROCESS_REQUEST, mockContext);

        assertEquals(JOURNEY_ERROR_PATH, response.get(JOURNEY));
    }

    @Test
    void shouldReturnErrorJourneyIfIdentityContinuityCheckDifferentBirthDate() throws Exception {
        ipvSessionItem = new IpvSessionItem();
        ipvSessionItem.setIpvSessionId(SESSION_ID);
        ipvSessionItem.setClientOAuthSessionId(CLIENT_SESSION_ID);
        ipvSessionItem.setCoiSubJourneyType(GIVEN_NAMES_ONLY);
        when(mockIpvSessionService.getIpvSession(SESSION_ID)).thenReturn(ipvSessionItem);
        when(mockClientOauthSessionDetailsService.getClientOAuthSession(CLIENT_SESSION_ID))
                .thenReturn(clientOAuthSessionItem);
        when(mockUserIdentityService.findIdentityClaim(any()))
                .thenReturn(Optional.of(IDENTITY_CLAIM_1))
                .thenReturn(Optional.of(IDENTITY_CLAIM_3));

        var response = identityContinuityCheckHandler.handleRequest(PROCESS_REQUEST, mockContext);

        assertEquals(JOURNEY_ERROR_PATH, response.get(JOURNEY));
    }

    @Test
    @MockitoSettings(strictness = LENIENT)
    void shouldReturnTrueWhenBirthDateAndFullNameAreSame() {
        when(mockUserIdentityService.getNormalizedName(IDENTITY_CLAIM_1, GIVEN_NAME_PROPERTY_NAME))
                .thenReturn("FirstName");
        when(mockUserIdentityService.getNormalizedName(IDENTITY_CLAIM_1, FAMILY_NAME_PROPERTY_NAME))
                .thenReturn("SecondName");

        boolean result =
                identityContinuityCheckHandler.isIdentityContinuityMatchGivenName(
                        IDENTITY_CLAIM_1, IDENTITY_CLAIM_1);

        assertTrue(result);
    }

    @Test
    @MockitoSettings(strictness = LENIENT)
    void shouldReturnFalseWhenBirthDateIsDifferent() {
        when(mockUserIdentityService.getNormalizedName(IDENTITY_CLAIM_1, GIVEN_NAME_PROPERTY_NAME))
                .thenReturn("FirstName");
        when(mockUserIdentityService.getNormalizedName(IDENTITY_CLAIM_1, FAMILY_NAME_PROPERTY_NAME))
                .thenReturn("SecondName");
        boolean result =
                identityContinuityCheckHandler.isIdentityContinuityMatchGivenName(
                        IDENTITY_CLAIM_1, IDENTITY_CLAIM_3);

        assertFalse(result);
    }

    //    @Test
    //    void shouldReturnFalseWhenFullNameIsDifferent() {
    //        IdentityClaim currentIdentity = new IdentityClaim("John Doe", "2000-01-01");
    //        IdentityClaim newIdentity = new IdentityClaim("Jane Doe", "2000-01-01");
    //
    //        boolean result =
    // identityContinuityCheckHandler.isIdentityContinuityGivenName(currentIdentity, newIdentity);
    //
    //        assertFalse(result);
    //    }
    //
    //    @Test
    //    void shouldReturnTrueWhenFullNameHasDiacriticsButIsSame() {
    //        IdentityClaim currentIdentity = new IdentityClaim("John Doe", "2000-01-01");
    //        IdentityClaim newIdentity = new IdentityClaim("Jöhn Döe", "2000-01-01");
    //
    //        boolean result =
    // identityContinuityCheckHandler.isIdentityContinuityGivenName(currentIdentity, newIdentity);
    //
    //        assertTrue(result);
    //    }
}
