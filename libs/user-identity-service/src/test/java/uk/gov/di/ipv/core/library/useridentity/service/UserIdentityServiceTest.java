package uk.gov.di.ipv.core.library.useridentity.service;

import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;
import org.junit.jupiter.params.provider.NullAndEmptySource;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.mockito.junit.jupiter.MockitoSettings;
import org.mockito.quality.Strictness;
import uk.gov.di.ipv.core.library.config.ConfigurationVariable;
import uk.gov.di.ipv.core.library.domain.ContraIndicatorConfig;
import uk.gov.di.ipv.core.library.domain.ErrorResponse;
import uk.gov.di.ipv.core.library.domain.IdentityClaim;
import uk.gov.di.ipv.core.library.domain.ReturnCode;
import uk.gov.di.ipv.core.library.domain.VerifiableCredential;
import uk.gov.di.ipv.core.library.dto.OauthCriConfig;
import uk.gov.di.ipv.core.library.enums.Vot;
import uk.gov.di.ipv.core.library.exceptions.CredentialParseException;
import uk.gov.di.ipv.core.library.exceptions.HttpResponseExceptionWithErrorBody;
import uk.gov.di.ipv.core.library.exceptions.UnrecognisedCiException;
import uk.gov.di.ipv.core.library.helpers.vocab.BirthDateGenerator;
import uk.gov.di.ipv.core.library.service.ConfigService;
import uk.gov.di.model.CheckDetails;
import uk.gov.di.model.ContraIndicator;
import uk.gov.di.model.DrivingPermitDetails;
import uk.gov.di.model.IdentityCheck;
import uk.gov.di.model.IdentityCheckCredential;
import uk.gov.di.model.IdentityCheckSubject;
import uk.gov.di.model.Mitigation;
import uk.gov.di.model.Name;
import uk.gov.di.model.PassportDetails;
import uk.gov.di.model.PostalAddress;
import uk.gov.di.model.SocialSecurityRecordDetails;
import uk.gov.di.model.VerifiableCredentialType;

import java.net.URI;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.stream.Stream;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;
import static org.mockito.quality.Strictness.LENIENT;
import static uk.gov.di.ipv.core.library.config.ConfigurationVariable.CI_SCORING_THRESHOLD;
import static uk.gov.di.ipv.core.library.config.ConfigurationVariable.COI_CHECK_FAMILY_NAME_CHARS;
import static uk.gov.di.ipv.core.library.config.ConfigurationVariable.COI_CHECK_GIVEN_NAME_CHARS;
import static uk.gov.di.ipv.core.library.config.ConfigurationVariable.CORE_VTM_CLAIM;
import static uk.gov.di.ipv.core.library.config.ConfigurationVariable.RETURN_CODES_ALWAYS_REQUIRED;
import static uk.gov.di.ipv.core.library.config.ConfigurationVariable.RETURN_CODES_NON_CI_BREACHING_P0;
import static uk.gov.di.ipv.core.library.domain.Cri.ADDRESS;
import static uk.gov.di.ipv.core.library.domain.Cri.BAV;
import static uk.gov.di.ipv.core.library.domain.Cri.DCMAW;
import static uk.gov.di.ipv.core.library.domain.Cri.EXPERIAN_FRAUD;
import static uk.gov.di.ipv.core.library.domain.Cri.PASSPORT;
import static uk.gov.di.ipv.core.library.fixtures.VcFixtures.*;
import static uk.gov.di.ipv.core.library.helpers.VerifiableCredentialGenerator.generateVerifiableCredential;
import static uk.gov.di.ipv.core.library.helpers.vocab.NameGenerator.NamePartGenerator.createNamePart;
import static uk.gov.di.model.NamePart.NamePartType.FAMILY_NAME;
import static uk.gov.di.model.NamePart.NamePartType.GIVEN_NAME;

@ExtendWith(MockitoExtension.class)
@MockitoSettings(strictness = Strictness.LENIENT)
class UserIdentityServiceTest {
    private static final String USER_ID_1 = "user-id-1";

    private final List<ContraIndicator> emptyContraIndicators = List.of();
    private final Map<ConfigurationVariable, String> paramsToMockForP2 =
            Map.of(CORE_VTM_CLAIM, "mock-vtm-claim");
    private final Map<ConfigurationVariable, String> paramsToMockForP0 =
            Map.of(CORE_VTM_CLAIM, "mock-vtm-claim");
    private final Map<ConfigurationVariable, String> paramsToMockForP0WithNoCi =
            Map.of(CORE_VTM_CLAIM, "mock-vtm-claim", RETURN_CODES_NON_CI_BREACHING_P0, "🐧");

    public static OauthCriConfig claimedIdentityConfig;

    @Mock private ConfigService mockConfigService;
    @InjectMocks private UserIdentityService userIdentityService;

    @BeforeAll
    static void beforeAllSetUp() throws Exception {
        claimedIdentityConfig =
                OauthCriConfig.builder()
                        .tokenUrl(new URI("http://example.com/token"))
                        .credentialUrl(new URI("http://example.com/credential"))
                        .authorizeUrl(new URI("http://example.com/authorize"))
                        .clientId("ipv-core")
                        .signingKey("test-jwk")
                        .encryptionKey("test-encryption-jwk")
                        .componentId("https://review-a.integration.account.gov.uk")
                        .clientCallbackUrl(new URI("http://example.com/redirect"))
                        .requiresApiKey(true)
                        .requiresAdditionalEvidence(false)
                        .build();
    }

    @Test
    void shouldReturnCredentialsFromDataStore() throws Exception {
        // Arrange
        var passportVc = vcWebPassportSuccessful();
        var fraudVc = vcWebPassportSuccessful();
        var vcs = List.of(passportVc, fraudVc);

        mockParamStoreCalls(paramsToMockForP2);

        // Act
        var credentials =
                userIdentityService.generateUserIdentity(
                        vcs, "test-sub", Vot.P2, Vot.P2, emptyContraIndicators);

        // Assert
        assertEquals(passportVc.getVcString(), credentials.getVcs().get(0));
        assertEquals(fraudVc.getVcString(), credentials.getVcs().get(1));
        assertEquals("test-sub", credentials.getSub());
    }

    @Test
    void shouldSetVotClaimToP2OnSuccessfulIdentityCheck() throws Exception {
        // Arrange
        var vcs = List.of(vcWebPassportSuccessful(), vcExperianFraudScoreTwo(), vcAddressOne());

        mockParamStoreCalls(paramsToMockForP2);

        // Act
        var credentials =
                userIdentityService.generateUserIdentity(
                        vcs, "test-sub", Vot.P2, Vot.P2, emptyContraIndicators);

        // Assert
        assertEquals(Vot.P2, credentials.getVot());
    }

    @Test
    void areVCsCorrelatedReturnsTrueWhenVcAreCorrelated() throws Exception {
        // Arrange
        var vcs =
                List.of(
                        generateVerifiableCredential(
                                USER_ID_1,
                                ADDRESS,
                                createCredentialWithNameAndBirthDate(
                                        "Jimbo", "Jones", "1000-01-01")),
                        generateVerifiableCredential(
                                USER_ID_1,
                                PASSPORT,
                                createCredentialWithNameAndBirthDate(
                                        "Jimbo", "Jones", "1000-01-01")),
                        generateVerifiableCredential(
                                USER_ID_1,
                                BAV,
                                createCredentialWithNameAndBirthDate(
                                        "Jimbo", "Jones", "1000-01-01")));

        // Act & Assert
        assertTrue(userIdentityService.areVcsCorrelated(vcs));
    }

    @Test
    void areVCsCorrelatedReturnFalseWhenNamesDiffer() throws Exception {
        // Arrange
        var vcs =
                List.of(
                        generateVerifiableCredential(
                                USER_ID_1,
                                PASSPORT,
                                createCredentialWithNameAndBirthDate(
                                        "Jimbo", "Jones", "1000-01-01")),
                        generateVerifiableCredential(
                                USER_ID_1,
                                PASSPORT,
                                createCredentialWithNameAndBirthDate(
                                        "Corky", "Jones", "1000-01-01")),
                        generateVerifiableCredential(
                                USER_ID_1,
                                PASSPORT,
                                createCredentialWithNameAndBirthDate(
                                        "Jimbo", "Jones", "1000-01-01")));

        // Act & Assert
        assertFalse(userIdentityService.areVcsCorrelated(vcs));
    }

    @Test
    void areVCsCorrelatedReturnFalseWhenNameDifferentForBavCRI() throws Exception {
        // Arrange
        var vcs =
                List.of(
                        generateVerifiableCredential(
                                USER_ID_1,
                                PASSPORT,
                                createCredentialWithNameAndBirthDate(
                                        "Jimbo", "Jones", "1000-01-01")),
                        generateVerifiableCredential(
                                USER_ID_1,
                                BAV,
                                createCredentialWithNameAndBirthDate(
                                        "Jimmy", "Jones",
                                        ""))); // BAV cri doesn't provide birthdate

        // Act & Assert
        assertFalse(userIdentityService.areVcsCorrelated(vcs));
    }

    @ParameterizedTest
    @NullAndEmptySource
    void areVCsCorrelatedShouldThrowExceptionWhenVcHasMissingGivenName(String missingName) {
        // Arrange
        var vcs =
                List.of(
                        generateVerifiableCredential(
                                USER_ID_1,
                                PASSPORT,
                                createCredentialWithNameAndBirthDate(
                                        "Jimbo", "Jones", "1000-01-01")),
                        generateVerifiableCredential(
                                USER_ID_1,
                                PASSPORT,
                                createCredentialWithNameAndBirthDate(
                                        missingName, "Jones", "1000-01-01")));

        // Act & Assert
        HttpResponseExceptionWithErrorBody thrownError =
                assertThrows(
                        HttpResponseExceptionWithErrorBody.class,
                        () -> userIdentityService.areVcsCorrelated(vcs));

        assertEquals(500, thrownError.getResponseCode());
        assertEquals(ErrorResponse.FAILED_NAME_CORRELATION, thrownError.getErrorResponse());
    }

    @ParameterizedTest
    @NullAndEmptySource
    void areVCsCorrelatedShouldThrowExceptionWhenVcHasMissingFamilyName(String missingName) {
        // Arrange
        var vcs =
                List.of(
                        generateVerifiableCredential(
                                USER_ID_1,
                                PASSPORT,
                                createCredentialWithNameAndBirthDate(
                                        "Jimbo", missingName, "1000-01-01")),
                        generateVerifiableCredential(
                                USER_ID_1,
                                EXPERIAN_FRAUD,
                                createCredentialWithNameAndBirthDate(
                                        "Jimbo", "Jones", "1000-01-01")));

        // Act & Assert
        HttpResponseExceptionWithErrorBody thrownError =
                assertThrows(
                        HttpResponseExceptionWithErrorBody.class,
                        () -> userIdentityService.areVcsCorrelated(vcs));

        assertEquals(500, thrownError.getResponseCode());
        assertEquals(ErrorResponse.FAILED_NAME_CORRELATION, thrownError.getErrorResponse());
    }

    @ParameterizedTest
    @NullAndEmptySource
    void areVCsCorrelatedShouldReturnTrueWhenAddressVcHasMissingName(String missing)
            throws Exception {
        // Arrange
        var vcs =
                List.of(
                        generateVerifiableCredential(
                                USER_ID_1,
                                EXPERIAN_FRAUD,
                                createCredentialWithNameAndBirthDate(
                                        "Jimbo", "Jones", "1000-01-01")),
                        generateVerifiableCredential(
                                USER_ID_1,
                                ADDRESS,
                                createCredentialWithNameAndBirthDate(
                                        missing, missing, "1000-01-01")));

        // Act & Assert
        assertTrue(userIdentityService.areVcsCorrelated(vcs));
    }

    @ParameterizedTest
    @NullAndEmptySource
    void areVCsCorrelatedShouldReturnFalseWhenMissingNameCredentialForBAVCRI(String missing) {
        // Arrange
        var vcs =
                List.of(
                        generateVerifiableCredential(
                                USER_ID_1,
                                PASSPORT,
                                createCredentialWithNameAndBirthDate(
                                        "Jimbo", "Jones", "1000-01-01")),
                        generateVerifiableCredential(
                                USER_ID_1,
                                DCMAW,
                                createCredentialWithNameAndBirthDate(
                                        "Jimbo", "Jones", "1000-01-01")),
                        generateVerifiableCredential(
                                USER_ID_1,
                                BAV,
                                createCredentialWithNameAndBirthDate(missing, "Jones", missing)));

        // Act & Assert
        HttpResponseExceptionWithErrorBody thrownError =
                assertThrows(
                        HttpResponseExceptionWithErrorBody.class,
                        () -> userIdentityService.areVcsCorrelated(vcs));

        assertEquals(500, thrownError.getResponseCode());
        assertEquals(ErrorResponse.FAILED_NAME_CORRELATION, thrownError.getErrorResponse());
    }

    @Test
    void areVCsCorrelatedShouldReturnFalseIfExtraGivenNameInVc() throws Exception {
        // Arrange
        var vcs =
                List.of(
                        generateVerifiableCredential(
                                USER_ID_1,
                                ADDRESS,
                                createCredentialWithNameAndBirthDate(
                                        "Jimbo", "Jones", "1000-01-01")),
                        generateVerifiableCredential(
                                USER_ID_1,
                                PASSPORT,
                                createCredentialWithNameAndBirthDate(
                                        "Jimbo", "Jimmy", "Jones", "1000-01-01")),
                        generateVerifiableCredential(
                                USER_ID_1,
                                BAV,
                                createCredentialWithNameAndBirthDate(
                                        "Jimbo", "Jones", "1000-01-01")));

        // Act & Assert
        assertFalse(userIdentityService.areVcsCorrelated(vcs));
    }

    @Test
    void areVCsCorrelatedReturnsFalseWhenBirthDatesDiffer() throws Exception {
        // Arrange
        var vcs =
                List.of(
                        generateVerifiableCredential(
                                USER_ID_1,
                                PASSPORT,
                                createCredentialWithNameAndBirthDate(
                                        "Jimbo", "Jones", "1000-01-01")),
                        generateVerifiableCredential(
                                USER_ID_1,
                                PASSPORT,
                                createCredentialWithNameAndBirthDate(
                                        "Jimbo", "Jones", "1000-01-01")),
                        generateVerifiableCredential(
                                USER_ID_1,
                                PASSPORT,
                                createCredentialWithNameAndBirthDate(
                                        "Jimbo", "Jones", "2000-01-01")));

        // Act & Assert
        assertFalse(userIdentityService.areVcsCorrelated(vcs));
    }

    @ParameterizedTest
    @NullAndEmptySource
    void areVCsCorrelatedShouldThrowExceptionWhenMissingBirthDateProperty(String missing) {
        // Arrange
        var vcs =
                List.of(
                        generateVerifiableCredential(
                                USER_ID_1,
                                ADDRESS,
                                createCredentialWithNameAndBirthDate(
                                        "Jimbo", "Jones", "1000-01-01")),
                        generateVerifiableCredential(
                                USER_ID_1,
                                PASSPORT,
                                createCredentialWithNameAndBirthDate("Jimbo", "Jones", missing)),
                        generateVerifiableCredential(
                                USER_ID_1,
                                EXPERIAN_FRAUD,
                                createCredentialWithNameAndBirthDate(
                                        "Jimbo", "Jones", "1000-01-01")));

        // Act & Assert
        HttpResponseExceptionWithErrorBody thrownError =
                assertThrows(
                        HttpResponseExceptionWithErrorBody.class,
                        () -> userIdentityService.areVcsCorrelated(vcs));

        assertEquals(500, thrownError.getResponseCode());
        assertEquals(ErrorResponse.FAILED_BIRTHDATE_CORRELATION, thrownError.getErrorResponse());
    }

    @ParameterizedTest
    @NullAndEmptySource
    void areVCsCorrelatedShouldReturnTrueWhenAddressHasMissingBirthDate(String missing)
            throws Exception {
        // Arrange
        var vcs =
                List.of(
                        generateVerifiableCredential(
                                USER_ID_1,
                                ADDRESS,
                                createCredentialWithNameAndBirthDate("Jimbo", "Jones", missing)),
                        generateVerifiableCredential(
                                USER_ID_1,
                                PASSPORT,
                                createCredentialWithNameAndBirthDate(
                                        "Jimbo", "Jones", "1000-01-01")),
                        generateVerifiableCredential(
                                USER_ID_1,
                                EXPERIAN_FRAUD,
                                createCredentialWithNameAndBirthDate(
                                        "Jimbo", "Jones", "1000-01-01")));

        // Act & Assert
        assertTrue(userIdentityService.areVcsCorrelated(vcs));
    }

    @Test
    void areVCsCorrelatedShouldReturnFalseIfBavHasDifferentBirthDate() throws Exception {
        // Arrange
        var vcs =
                List.of(
                        generateVerifiableCredential(
                                USER_ID_1,
                                ADDRESS,
                                createCredentialWithNameAndBirthDate(
                                        "Jimbo", "Jones", "1000-01-01")),
                        generateVerifiableCredential(
                                USER_ID_1,
                                PASSPORT,
                                createCredentialWithNameAndBirthDate(
                                        "Jimbo", "Jones", "1000-01-01")),
                        generateVerifiableCredential(
                                USER_ID_1,
                                BAV,
                                createCredentialWithNameAndBirthDate(
                                        "Jimbo", "Jones", "2000-01-01")));

        // Act & Assert
        assertFalse(userIdentityService.areVcsCorrelated(vcs));
    }

    @Test
    void areVCsCorrelatedShouldNotIncludeVCsForNameNotDeemedSuccessful() throws Exception {
        // Arrange
        var vcs =
                List.of(
                        generateVerifiableCredential(
                                USER_ID_1,
                                ADDRESS,
                                createCredentialWithNameAndBirthDate(
                                        "Jimbo", "Jones", "1000-01-01")),
                        generateVerifiableCredential(
                                USER_ID_1,
                                PASSPORT,
                                createCredentialWithNameAndBirthDate(
                                        "Corky", "Jones", "1000-01-01", false)),
                        generateVerifiableCredential(
                                USER_ID_1,
                                EXPERIAN_FRAUD,
                                createCredentialWithNameAndBirthDate(
                                        "Jimbo", "Jones", "1000-01-01")));

        // Act & Assert
        assertTrue(userIdentityService.areVcsCorrelated(vcs));
    }

    @Test
    void areVCsCorrelatedShouldNotIncludeVCsForDOBNotDeemedSuccessful() throws Exception {
        // Arrange
        var vcs =
                List.of(
                        generateVerifiableCredential(
                                USER_ID_1,
                                ADDRESS,
                                createCredentialWithNameAndBirthDate(
                                        "Jimbo", "Jones", "1000-01-01")),
                        generateVerifiableCredential(
                                USER_ID_1,
                                PASSPORT,
                                createCredentialWithNameAndBirthDate(
                                        "Jimbo", "Jones", "1000-01-01")),
                        generateVerifiableCredential(
                                USER_ID_1,
                                EXPERIAN_FRAUD,
                                createCredentialWithNameAndBirthDate(
                                        "Jimbo", "Jones", "2000-01-01", false)));

        // Act & Assert
        assertTrue(userIdentityService.areVcsCorrelated(vcs));
    }

    @Test
    void areVCsCorrelatedReturnsFalseWhenExtraBirthDateInVc() throws Exception {
        // Arrange
        var vcs =
                List.of(
                        generateVerifiableCredential(
                                USER_ID_1,
                                PASSPORT,
                                createCredentialWithNameAndBirthDate(
                                        "Jimbo", "Jones", "1000-01-01")),
                        generateVerifiableCredential(
                                USER_ID_1,
                                PASSPORT,
                                createCredentialWithNameAndBirthDate(
                                        "Jimbo", "Jones", "1000-01-01")),
                        generateVerifiableCredential(
                                USER_ID_1,
                                PASSPORT,
                                createCredentialWithNameAndBirthDate(
                                        "Jimbo", "Jones", List.of("1000-01-01", "2000-01-01"))));

        // Act & Assert
        assertFalse(userIdentityService.areVcsCorrelated(vcs));
    }

    @Nested
    class AreNamesAndDobCorrelated {
        private VerifiableCredential jimboJones2000 =
                generateVerifiableCredential(
                        USER_ID_1,
                        PASSPORT,
                        createCredentialWithNameAndBirthDate("Jimbo", "Jones", "2000-01-01"));
        private VerifiableCredential jimboSmith2000 =
                generateVerifiableCredential(
                        USER_ID_1,
                        PASSPORT,
                        createCredentialWithNameAndBirthDate("Jimbo", "SMITH", "2000-01-01"));
        private VerifiableCredential timmyJones2000 =
                generateVerifiableCredential(
                        USER_ID_1,
                        PASSPORT,
                        createCredentialWithNameAndBirthDate("Timmy", "Jones", "2000-01-01"));
        private VerifiableCredential timmySmith2000 =
                generateVerifiableCredential(
                        USER_ID_1,
                        PASSPORT,
                        createCredentialWithNameAndBirthDate("Timmy", "Smith", "2000-01-01"));
        private VerifiableCredential jimboJones2002 =
                generateVerifiableCredential(
                        USER_ID_1,
                        PASSPORT,
                        createCredentialWithNameAndBirthDate("Timmy", "Smith", "2002-02-02"));
        private VerifiableCredential jimboJonathonJones2002 =
                generateVerifiableCredential(
                        USER_ID_1,
                        PASSPORT,
                        createCredentialWithNameAndBirthDate(
                                "Timmy", "Jonathon", "Smith", "2002-02-02"));

        @BeforeEach
        void setup() {
            when(mockConfigService.getParameter(COI_CHECK_FAMILY_NAME_CHARS)).thenReturn("5");
        }

        @Test
        void shouldReturnTrueForCorrelatedGivenNamesAndDobAndDifferentFamilyNames()
                throws Exception {
            // Arrange
            var vcs = List.of(jimboJones2000, jimboJones2000, jimboSmith2000);

            // Act & Assert
            assertTrue(userIdentityService.areNamesAndDobCorrelated(vcs));
        }

        @Test
        void shouldReturnTrueForCorrelatedFamilyNamesAndDobAndDifferentGivenNames()
                throws Exception {
            // Arrange
            var vcs = List.of(jimboJones2000, jimboJones2000, timmyJones2000);

            // Act & Assert
            assertTrue(userIdentityService.areNamesAndDobCorrelated(vcs));
        }

        @Test
        void shouldReturnTrueWhenFamilyNameShorterThanCheckChars() throws Exception {
            // Arrange
            when(mockConfigService.getParameter(COI_CHECK_FAMILY_NAME_CHARS)).thenReturn("500");
            var vcs = List.of(jimboJones2000, jimboJones2000, jimboSmith2000);

            // Act & Assert
            assertTrue(userIdentityService.areNamesAndDobCorrelated(vcs));
        }

        @Test
        void shouldReturnFalseIfGivenNamesAndFamilyNamesBothDiffer() throws Exception {
            // Arrange
            var vcs = List.of(jimboJones2000, jimboJones2000, timmySmith2000);

            // Act & Assert
            assertFalse(userIdentityService.areNamesAndDobCorrelated(vcs));
        }

        @Test
        void shouldReturnFalseIfExtraGivenName() throws Exception {
            // Arrange
            var vcs = List.of(jimboJones2000, jimboJones2000, jimboJonathonJones2002);

            // Act & Assert
            assertFalse(userIdentityService.areNamesAndDobCorrelated(vcs));
        }

        @Test
        void shouldReturnFalseIfDobDiffers() throws Exception {
            // Arrange
            var vcs = List.of(jimboJones2000, jimboJones2000, jimboJones2002);

            // Act & Assert
            assertFalse(userIdentityService.areNamesAndDobCorrelated(vcs));
        }

        @ParameterizedTest
        @NullAndEmptySource
        void shouldThrowIfMissingGivenName(String missingName) {
            // Arrange
            var vcs =
                    List.of(
                            jimboJones2000,
                            jimboJones2000,
                            generateVerifiableCredential(
                                    USER_ID_1,
                                    PASSPORT,
                                    createCredentialWithNameAndBirthDate(
                                            missingName, "Jones", "1000-01-01")));

            // Act
            HttpResponseExceptionWithErrorBody thrownError =
                    assertThrows(
                            HttpResponseExceptionWithErrorBody.class,
                            () -> userIdentityService.areNamesAndDobCorrelated(vcs));

            // Assert
            assertEquals(500, thrownError.getResponseCode());
            assertEquals(ErrorResponse.FAILED_NAME_CORRELATION, thrownError.getErrorResponse());
        }

        @MockitoSettings(strictness = LENIENT)
        @ParameterizedTest
        @NullAndEmptySource
        void shouldThrowIfMissingFamilyName(String missingName) {
            // Arrange
            var vcs =
                    List.of(
                            jimboJones2000,
                            jimboJones2000,
                            generateVerifiableCredential(
                                    USER_ID_1,
                                    PASSPORT,
                                    createCredentialWithNameAndBirthDate(
                                            "Dimbo", missingName, "1000-01-01")));

            // Act
            HttpResponseExceptionWithErrorBody thrownError =
                    assertThrows(
                            HttpResponseExceptionWithErrorBody.class,
                            () -> userIdentityService.areNamesAndDobCorrelated(vcs));

            // Assert
            assertEquals(500, thrownError.getResponseCode());
            assertEquals(ErrorResponse.FAILED_NAME_CORRELATION, thrownError.getErrorResponse());
        }

        @ParameterizedTest
        @NullAndEmptySource
        void shouldThrowIfMissingDob(String missingDob) {
            // Arrange
            var vcs =
                    List.of(
                            jimboJones2000,
                            jimboJones2000,
                            generateVerifiableCredential(
                                    USER_ID_1,
                                    PASSPORT,
                                    createCredentialWithNameAndBirthDate(
                                            "Jimbo", "Jones", missingDob)));

            // Act
            HttpResponseExceptionWithErrorBody thrownError =
                    assertThrows(
                            HttpResponseExceptionWithErrorBody.class,
                            () -> userIdentityService.areNamesAndDobCorrelated(vcs));

            // Assert
            assertEquals(500, thrownError.getResponseCode());
            assertEquals(
                    ErrorResponse.FAILED_BIRTHDATE_CORRELATION, thrownError.getErrorResponse());
        }
    }

    @Test
    void shouldSetIdentityClaimWhenVotIsP2() throws Exception {
        // Arrange
        var vcs = List.of(vcWebPassportSuccessful(), vcExperianFraudScoreTwo(), vcAddressOne());

        mockParamStoreCalls(paramsToMockForP2);

        // Act
        var credentials =
                userIdentityService.generateUserIdentity(
                        vcs, "test-sub", Vot.P2, Vot.P2, emptyContraIndicators);

        // Assert
        IdentityClaim identityClaim = credentials.getIdentityClaim();

        assertEquals(GIVEN_NAME, identityClaim.getName().get(0).getNameParts().get(0).getType());
        assertEquals("KENNETH", identityClaim.getName().get(0).getNameParts().get(0).getValue());

        assertEquals("1965-07-08", identityClaim.getBirthDate().get(0).getValue());
    }

    @Test
    void shouldSetIdentityClaimWhenVotIsP2MissingName() throws Exception {
        // Arrange
        var vcs =
                List.of(
                        vcWebPassportMissingName(),
                        vcWebPassportMissingBirthDate(),
                        vcExperianFraudScoreTwo(),
                        vcAddressOne());

        mockParamStoreCalls(paramsToMockForP2);

        // Act
        var credentials =
                userIdentityService.generateUserIdentity(
                        vcs, "test-sub", Vot.P2, Vot.P2, emptyContraIndicators);

        // Assert
        IdentityClaim identityClaim = credentials.getIdentityClaim();

        assertEquals(GIVEN_NAME, identityClaim.getName().get(0).getNameParts().get(0).getType());
        assertEquals("KENNETH", identityClaim.getName().get(0).getNameParts().get(0).getValue());

        assertEquals("1965-07-08", identityClaim.getBirthDate().get(0).getValue());
    }

    @Test
    void shouldNotSetIdentityClaimWhenVotIsP0() throws Exception {
        // Arrange
        var vcs = List.of(vcWebPassportSuccessful(), vcExperianFraudScoreOne());

        mockParamStoreCalls(paramsToMockForP0WithNoCi);
        when(mockConfigService.getParameter(CI_SCORING_THRESHOLD, "P2")).thenReturn("0");

        // Act
        var credentials =
                userIdentityService.generateUserIdentity(
                        vcs, "test-sub", Vot.P0, Vot.P2, emptyContraIndicators);

        // Assert
        assertNull(credentials.getIdentityClaim());
    }

    @Test
    void shouldGetCorrectVot() throws Exception {
        // Arrange
        var vc = vcHmrcMigrationPCL250();

        // Act
        var vot = userIdentityService.getVot(vc);

        // Assert
        assertEquals(Vot.PCL250, vot);
    }

    @Test
    void shouldThrowForInvalidVot() {
        // Arrange
        var vc = vcInvalidVot();

        // Act
        IllegalArgumentException thrownException =
                assertThrows(IllegalArgumentException.class, () -> userIdentityService.getVot(vc));

        // Assert
        assertEquals(
                "No enum constant uk.gov.di.ipv.core.library.enums.Vot.not-a-vot",
                thrownException.getMessage());
    }

    @Test
    void shouldThrowExceptionWhenMissingNameProperty() {
        // Arrange
        var vcs = List.of(vcWebPassportMissingName(), vcExperianFraudScoreTwo());

        when(mockConfigService.getParameter(CORE_VTM_CLAIM)).thenReturn("mock-vtm-claim");

        // Act & Assert
        HttpResponseExceptionWithErrorBody thrownError =
                assertThrows(
                        HttpResponseExceptionWithErrorBody.class,
                        () ->
                                userIdentityService.generateUserIdentity(
                                        vcs, "test-sub", Vot.P2, Vot.P2, emptyContraIndicators));

        assertEquals(500, thrownError.getResponseCode());
        assertEquals(
                ErrorResponse.FAILED_TO_GENERATE_IDENTITY_CLAIM, thrownError.getErrorResponse());
    }

    @Test
    void shouldThrowExceptionWhenMissingBirthDateProperty() {
        // Arrange
        var vcs = List.of(vcWebPassportMissingBirthDate(), vcExperianFraudScoreTwo());

        when(mockConfigService.getParameter(CORE_VTM_CLAIM)).thenReturn("mock-vtm-claim");

        // Act & Assert
        HttpResponseExceptionWithErrorBody thrownError =
                assertThrows(
                        HttpResponseExceptionWithErrorBody.class,
                        () ->
                                userIdentityService.generateUserIdentity(
                                        vcs, "test-sub", Vot.P2, Vot.P2, emptyContraIndicators));

        assertEquals(500, thrownError.getResponseCode());
        assertEquals(
                ErrorResponse.FAILED_TO_GENERATE_IDENTITY_CLAIM, thrownError.getErrorResponse());
    }

    @Test
    void shouldSetPassportClaimWhenVotIsP2() throws Exception {
        // Arrange
        mockParamStoreCalls(paramsToMockForP2);

        var vcs = List.of(vcWebPassportSuccessful(), vcExperianFraudScoreTwo(), vcAddressOne());

        // Act
        var credentials =
                userIdentityService.generateUserIdentity(
                        vcs, "test-sub", Vot.P2, Vot.P2, emptyContraIndicators);

        // Assert
        PassportDetails passportClaim = credentials.getPassportClaim().get(0);

        assertEquals("321654987", passportClaim.getDocumentNumber());
        assertEquals("2030-01-01", passportClaim.getExpiryDate());
    }

    @ParameterizedTest
    @MethodSource("VcsWithPassportClaim")
    void shouldSetPassportClaimWhenVotIsP2(VerifiableCredential vcWithPassportClaim)
            throws Exception {
        // Arrange
        mockParamStoreCalls(paramsToMockForP2);

        var vcs = List.of(vcWithPassportClaim, vcExperianFraudScoreTwo(), vcAddressOne());

        // Act
        var credentials =
                userIdentityService.generateUserIdentity(
                        vcs, "test-sub", Vot.P2, Vot.P2, emptyContraIndicators);

        // Assert
        assertNotNull(credentials.getPassportClaim().get(0));
    }

    private static Stream<Arguments> VcsWithPassportClaim() {
        return Stream.of(
                Arguments.of(vcWebPassportSuccessful()),
                Arguments.of(vcDcmawPassport()),
                Arguments.of(vcF2fPassportPhotoM1a()));
    }

    @Test
    void shouldNotSetPassportClaimWhenVotIsP0() throws Exception {
        // Arrange
        var vcs = List.of(vcWebPassportSuccessful(), vcExperianFraudScoreOne());

        mockParamStoreCalls(paramsToMockForP0WithNoCi);
        when(mockConfigService.getParameter(CI_SCORING_THRESHOLD, "P2")).thenReturn("0");

        // Act
        var credentials =
                userIdentityService.generateUserIdentity(
                        vcs, "test-sub", Vot.P0, Vot.P2, emptyContraIndicators);

        // Assert
        assertNull(credentials.getPassportClaim());
    }

    @Test
    void shouldReturnNullWhenMissingPassportProperty() throws Exception {
        // Arrange
        var vcs =
                List.of(
                        vcWebPassportMissingPassportDetails(),
                        vcExperianFraudScoreTwo(),
                        vcAddressOne());

        mockParamStoreCalls(paramsToMockForP2);

        // Act
        var credentials =
                userIdentityService.generateUserIdentity(
                        vcs, "test-sub", Vot.P2, Vot.P2, emptyContraIndicators);

        // Assert
        assertNull(credentials.getPassportClaim());
    }

    @Test
    void shouldReturnNullWhenEmptyPassportProperty() throws Exception {
        // Arrange
        var vcs =
                List.of(
                        vcWebPassportEmptyPassportDetails(),
                        vcExperianFraudScoreTwo(),
                        vcAddressOne());

        mockParamStoreCalls(paramsToMockForP2);

        // Act
        var credentials =
                userIdentityService.generateUserIdentity(
                        vcs, "test-sub", Vot.P2, Vot.P2, emptyContraIndicators);

        // Assert
        assertNull(credentials.getPassportClaim());
    }

    @Test
    void generateUserIdentityShouldReturnEmptyClaimIfClaimIsIncorrectType() throws Exception {
        // Arrange
        var vcs =
                List.of(vcWebPassportClaimInvalidType(), vcExperianFraudScoreTwo(), vcAddressOne());

        // Act
        var credentials =
                userIdentityService.generateUserIdentity(
                        vcs, "test-sub", Vot.P2, Vot.P2, emptyContraIndicators);

        // Assert
        assertNull(credentials.getPassportClaim());
    }

    @Test
    void generateUserIdentityShouldSetNinoClaimWhenVotIsP2() throws Exception {
        // Arrange
        mockParamStoreCalls(paramsToMockForP2);

        var vcs =
                List.of(
                        vcWebDrivingPermitDvaValid(),
                        vcExperianFraudScoreTwo(),
                        vcAddressOne(),
                        vcNinoIdentityCheckSuccessful());

        // Act
        var credentials =
                userIdentityService.generateUserIdentity(
                        vcs, "test-sub", Vot.P2, Vot.P2, emptyContraIndicators);

        // Assert
        SocialSecurityRecordDetails ninoClaim = credentials.getNinoClaim().get(0);
        assertEquals("AA000003D", ninoClaim.getPersonalNumber());
    }

    @Test
    void generateUserIdentityShouldNotSetNinoClaimWhenVotIsP0() throws Exception {
        // Arrange
        var vcs =
                List.of(
                        vcWebDrivingPermitDvaValid(),
                        vcExperianFraudScoreOne(),
                        vcNinoIdentityCheckSuccessful());

        mockParamStoreCalls(paramsToMockForP0WithNoCi);
        when(mockConfigService.getParameter(CI_SCORING_THRESHOLD, "P2")).thenReturn("0");

        // Act
        var credentials =
                userIdentityService.generateUserIdentity(
                        vcs, "test-sub", Vot.P0, Vot.P2, emptyContraIndicators);

        // Assert
        assertNull(credentials.getNinoClaim());
    }

    @Test
    void generateUserIdentityShouldReturnEmptyNinoClaimWhenMissingNinoProperty() throws Exception {
        // Arrange
        var vcs =
                List.of(
                        vcWebDrivingPermitDvaValid(),
                        vcExperianFraudScoreTwo(),
                        vcAddressOne(),
                        vcNinoIdentityCheckMissingSocialSecurityRecord());

        mockParamStoreCalls(paramsToMockForP2);

        // Act
        var credentials =
                userIdentityService.generateUserIdentity(
                        vcs, "test-sub", Vot.P2, Vot.P2, emptyContraIndicators);

        // Assert
        assertNull(credentials.getNinoClaim());
    }

    @Test
    void generateUserIdentityShouldReturnEmptyNinoClaimWhenMissingNinoVc() throws Exception {
        // Arrange
        var vcs = List.of(vcWebDrivingPermitDvaValid(), vcExperianFraudScoreTwo(), vcAddressOne());

        mockParamStoreCalls(paramsToMockForP2);

        // Act
        var credentials =
                userIdentityService.generateUserIdentity(
                        vcs, "test-sub", Vot.P2, Vot.P2, emptyContraIndicators);

        // Assert
        assertNull(credentials.getNinoClaim());
    }

    @Test
    void generateUserIdentityShouldReturnEmptyNinoClaimWhenNinoVcIsUnsuccessful() throws Exception {
        // Arrange
        var vcs =
                List.of(
                        vcWebDrivingPermitDvaValid(),
                        vcExperianFraudScoreTwo(),
                        vcAddressOne(),
                        vcNinoIdentityCheckUnsuccessful());

        mockParamStoreCalls(paramsToMockForP2);

        // Act
        var credentials =
                userIdentityService.generateUserIdentity(
                        vcs, "test-sub", Vot.P2, Vot.P2, emptyContraIndicators);

        // Assert
        assertNull(credentials.getNinoClaim());
    }

    @Test
    void generateUserIdentityShouldReturnEmptyClaimIfNinoVcPropertyIsEmpty() throws Exception {
        // Arrange
        var vcs =
                List.of(
                        vcWebDrivingPermitDvaValid(),
                        vcExperianFraudScoreTwo(),
                        vcAddressOne(),
                        vcNinoIdentityCheckEmptySocialSecurityRecord());

        mockParamStoreCalls(paramsToMockForP2);

        // Act
        var credentials =
                userIdentityService.generateUserIdentity(
                        vcs, "test-sub", Vot.P2, Vot.P2, emptyContraIndicators);

        // Assert
        assertNull(credentials.getNinoClaim());
    }

    @Test
    void generateUserIdentityShouldEmptyClaimIfNinoVcIsIncorrectType() throws Exception {
        // Arrange
        var vcs =
                List.of(
                        vcWebDrivingPermitDvaValid(),
                        vcExperianFraudScoreTwo(),
                        vcAddressOne(),
                        vcNinoInvalidVcType());

        mockParamStoreCalls(paramsToMockForP2);

        // Act
        var credentials =
                userIdentityService.generateUserIdentity(
                        vcs, "test-sub", Vot.P2, Vot.P2, emptyContraIndicators);

        // Assert
        assertNull(credentials.getNinoClaim());
    }

    @Test
    void shouldSetSubClaimOnUserIdentity() throws Exception {
        // Arrange
        mockParamStoreCalls(paramsToMockForP2);

        // Act
        var credentials =
                userIdentityService.generateUserIdentity(
                        List.of(), "test-sub", Vot.P2, Vot.P2, emptyContraIndicators);

        // Assert
        assertEquals("test-sub", credentials.getSub());
    }

    @Test
    void shouldSetVtmClaimOnUserIdentity() throws Exception {
        // Arrange
        mockParamStoreCalls(paramsToMockForP2);

        // Act
        var credentials =
                userIdentityService.generateUserIdentity(
                        List.of(), "test-sub", Vot.P2, Vot.P2, emptyContraIndicators);

        // Assert
        assertEquals("mock-vtm-claim", credentials.getVtm());
    }

    @Test
    void generateUserIdentityShouldSetAddressClaimOnUserIdentity() throws Exception {
        // Arrange
        var vcs = List.of(vcWebPassportSuccessful(), vcExperianFraudScoreTwo(), vcAddressTwo());

        mockParamStoreCalls(paramsToMockForP2);

        // Act
        var userIdentity =
                userIdentityService.generateUserIdentity(
                        vcs, "test-sub", Vot.P2, Vot.P2, emptyContraIndicators);

        // Assert
        // There is one address in the claims set
        PostalAddress address = userIdentity.getAddressClaim().get(0);

        assertEquals("221B", address.getBuildingName());
        assertEquals("MILTON ROAD", address.getStreetName());
        assertEquals("Milton Keynes", address.getAddressLocality());
        assertEquals("MK15 5BX", address.getPostalCode());
        assertEquals("2024-01-01", address.getValidFrom());
    }

    @Test
    void generateUserIdentityShouldThrowIfNoAddressesInAddressVC() {
        // Arrange
        var vcs = List.of(vcWebPassportSuccessful(), vcExperianFraudScoreTwo(), vcAddressEmpty());

        when(mockConfigService.getParameter(CORE_VTM_CLAIM)).thenReturn("mock-vtm-claim");

        // Act & Assert
        HttpResponseExceptionWithErrorBody thrownException =
                assertThrows(
                        HttpResponseExceptionWithErrorBody.class,
                        () ->
                                userIdentityService.generateUserIdentity(
                                        vcs, "test-sub", Vot.P2, Vot.P2, emptyContraIndicators));

        assertEquals(500, thrownException.getResponseCode());
        assertEquals(
                ErrorResponse.FAILED_TO_GENERATE_ADDRESS_CLAIM, thrownException.getErrorResponse());
    }

    @Test
    void generateUserIdentityShouldThrowIfAddressVcHasNoCredentialSubject() {
        // Arrange
        var vcs =
                List.of(
                        vcWebPassportSuccessful(),
                        vcExperianFraudScoreTwo(),
                        vcAddressNoCredentialSubject());

        when(mockConfigService.getParameter(CORE_VTM_CLAIM)).thenReturn("mock-vtm-claim");

        // Act & Assert
        HttpResponseExceptionWithErrorBody thrownException =
                assertThrows(
                        HttpResponseExceptionWithErrorBody.class,
                        () ->
                                userIdentityService.generateUserIdentity(
                                        vcs, "test-sub", Vot.P2, Vot.P2, emptyContraIndicators));

        assertEquals(500, thrownException.getResponseCode());
        assertEquals(
                ErrorResponse.FAILED_TO_GENERATE_ADDRESS_CLAIM, thrownException.getErrorResponse());
    }

    @Test
    void shouldNotSetAddressClaimWhenVotIsP0() throws Exception {
        // Arrange
        var vcs = List.of(vcExperianFraudScoreOne(), vcExperianFraudScoreTwo(), vcAddressTwo());

        mockParamStoreCalls(paramsToMockForP0WithNoCi);
        when(mockConfigService.getParameter(CI_SCORING_THRESHOLD, "P2")).thenReturn("0");

        // Act
        var credentials =
                userIdentityService.generateUserIdentity(
                        vcs, "test-sub", Vot.P0, Vot.P2, emptyContraIndicators);

        // Assert
        assertNull(credentials.getAddressClaim());
    }

    @Test
    void shouldSetDrivingPermitClaimWhenVotIsP2() throws Exception {
        // Arrange
        var vcs = List.of(vcWebDrivingPermitDvlaValid(), vcExperianFraudScoreOne(), vcAddressOne());

        mockParamStoreCalls(paramsToMockForP2);

        // Act
        var credentials =
                userIdentityService.generateUserIdentity(
                        vcs, "test-sub", Vot.P2, Vot.P2, emptyContraIndicators);

        // Assert
        DrivingPermitDetails drivingPermitClaim = credentials.getDrivingPermitClaim().get(0);

        assertEquals("PARKE710112PBFGA", drivingPermitClaim.getPersonalNumber());
        assertEquals("123456", drivingPermitClaim.getIssueNumber());
        assertEquals("2032-02-02", drivingPermitClaim.getExpiryDate());
    }

    @ParameterizedTest
    @MethodSource("VcsWithDrivingPermitClaim")
    void shouldSetDrivingPermitClaimForAllowedCris(VerifiableCredential vcWithDrivingPermitClaim)
            throws Exception {
        // Arrange
        var vcs = List.of(vcWithDrivingPermitClaim, vcExperianFraudScoreOne(), vcAddressOne());

        mockParamStoreCalls(paramsToMockForP2);

        // Act
        var credentials =
                userIdentityService.generateUserIdentity(
                        vcs, "test-sub", Vot.P2, Vot.P2, emptyContraIndicators);

        // Assert
        assertNotNull(credentials.getDrivingPermitClaim().get(0));
    }

    private static Stream<Arguments> VcsWithDrivingPermitClaim() {
        return Stream.of(
                Arguments.of(vcWebDrivingPermitDvaValid()),
                Arguments.of(vcDcmawDrivingPermitDvaM1b()),
                Arguments.of(vcF2fDrivingPermitDvaPhotoM1a()));
    }

    @Test
    void shouldNotSetDrivingPermitClaimWhenVotIsP0() throws Exception {
        // Arrange
        var vcs = List.of(vcWebDrivingPermitDvaValid(), vcExperianFraudScoreOne(), vcAddressOne());

        mockParamStoreCalls(paramsToMockForP0WithNoCi);
        when(mockConfigService.getParameter(CI_SCORING_THRESHOLD, "P2")).thenReturn("0");

        // Act
        var credentials =
                userIdentityService.generateUserIdentity(
                        vcs, "test-sub", Vot.P0, Vot.P2, emptyContraIndicators);

        // Assert
        List<DrivingPermitDetails> drivingPermitClaim = credentials.getDrivingPermitClaim();

        assertNull(drivingPermitClaim);
    }

    @Test
    void shouldNotSetDrivingPermitClaimWhenDrivingPermitVCIsMissing() throws Exception {
        // Arrange
        var vcs = List.of(vcWebPassportSuccessful(), vcExperianFraudScoreTwo(), vcAddressOne());

        mockParamStoreCalls(paramsToMockForP2);

        // Act
        var credentials =
                userIdentityService.generateUserIdentity(
                        vcs, "test-sub", Vot.P2, Vot.P2, emptyContraIndicators);

        // Assert
        List<DrivingPermitDetails> drivingPermitClaim = credentials.getDrivingPermitClaim();

        assertNull(drivingPermitClaim);
    }

    @Test
    void shouldNotSetDrivingPermitClaimWhenDrivingPermitVCFailed() throws Exception {
        // Arrange
        var vcs =
                List.of(
                        vcWebDrivingPermitFailedChecks(),
                        vcWebPassportSuccessful(),
                        vcAddressOne(),
                        vcExperianFraudScoreTwo());

        mockParamStoreCalls(paramsToMockForP2);

        // Act
        var credentials =
                userIdentityService.generateUserIdentity(
                        vcs, "test-sub", Vot.P2, Vot.P2, emptyContraIndicators);

        // Assert
        List<DrivingPermitDetails> drivingPermitClaim = credentials.getDrivingPermitClaim();

        assertNull(drivingPermitClaim);
    }

    @Test
    void shouldReturnNullWhenMissingDrivingPermitProperty() throws Exception {
        // Arrange
        var vcs = List.of(vcWebDrivingPermitMissingDrivingPermit());

        mockParamStoreCalls(paramsToMockForP2);

        // Act
        var credentials =
                userIdentityService.generateUserIdentity(
                        vcs, "test-sub", Vot.P2, Vot.P2, emptyContraIndicators);

        // Assert
        assertNull(credentials.getDrivingPermitClaim());
    }

    @Test
    void shouldReturnNullWhenEmptyDrivingPermitProperty() throws Exception {
        // Arrange
        var vcs = List.of(vcWebDrivingPermitEmptyDrivingPermit());

        mockParamStoreCalls(paramsToMockForP2);

        // Act
        var credentials =
                userIdentityService.generateUserIdentity(
                        vcs, "test-sub", Vot.P2, Vot.P2, emptyContraIndicators);

        // Assert
        assertNull(credentials.getDrivingPermitClaim());
    }

    @Test
    void generateUserIdentityShouldReturnEmptyClaimIfDrivingPermitVcIsIncorrectType()
            throws Exception {
        // Arrange
        var vcs =
                List.of(
                        vcWebDrivingPermitIncorrectType(),
                        vcExperianFraudScoreTwo(),
                        vcAddressOne());

        mockParamStoreCalls(paramsToMockForP2);

        // Act
        var credentials =
                userIdentityService.generateUserIdentity(
                        vcs, "test-sub", Vot.P2, Vot.P2, emptyContraIndicators);

        // Assert
        assertNull(credentials.getDrivingPermitClaim());
    }

    @Test
    void generateUserIdentityShouldSetExitCodeWhenP2AndAlwaysRequiredCiPresent() throws Exception {
        // Arrange
        mockParamStoreCalls(paramsToMockForP2);
        when(mockConfigService.getParameter(RETURN_CODES_ALWAYS_REQUIRED)).thenReturn("🦆,🐧");
        when(mockConfigService.getContraIndicatorConfigMap())
                .thenReturn(
                        Map.of(
                                "X01", new ContraIndicatorConfig("X01", 4, -3, "🦆"),
                                "X02", new ContraIndicatorConfig("X02", 4, -3, "2"),
                                "Z03", new ContraIndicatorConfig("Z03", 4, -3, "3")));

        var contraIndicators = List.of(createCi("X01"), createCi("X02"), createCi("Z03"));

        // Act
        var userIdentity =
                userIdentityService.generateUserIdentity(
                        List.of(), "test-sub", Vot.P2, Vot.P2, contraIndicators);

        // Assert
        assertEquals(List.of(new ReturnCode("🦆")), userIdentity.getReturnCode());
    }

    @Test
    void generateUserIdentityShouldSetEmptyExitCodeWhenP2AndAlwaysRequiredCiNotPresent()
            throws Exception {
        // Arrange
        mockParamStoreCalls(paramsToMockForP2);

        // Act
        var userIdentity =
                userIdentityService.generateUserIdentity(
                        List.of(), "test-sub", Vot.P2, Vot.P2, emptyContraIndicators);

        assertEquals(List.of(), userIdentity.getReturnCode());
    }

    @Test
    void generateUserIdentityShouldThrowWhenP2AndCiCodeNotFound() {
        // Arrange
        var emptyList = new ArrayList<VerifiableCredential>();
        when(mockConfigService.getParameter(CORE_VTM_CLAIM)).thenReturn("mock-vtm-claim");
        when(mockConfigService.getContraIndicatorConfigMap())
                .thenReturn(Map.of("X01", new ContraIndicatorConfig("X01", 4, -3, "1")));

        var contraIndicators = List.of(createCi("wat"));

        // Act & Assert
        assertThrows(
                UnrecognisedCiException.class,
                () ->
                        userIdentityService.generateUserIdentity(
                                emptyList, "test-sub", Vot.P2, Vot.P2, contraIndicators));
    }

    @Test
    void generateUserIdentityShouldSetExitCodeWhenBreachingCiThreshold() throws Exception {
        // Arrange
        mockParamStoreCalls(paramsToMockForP0);
        when(mockConfigService.getParameter(CI_SCORING_THRESHOLD, "P2")).thenReturn("0");
        when(mockConfigService.getContraIndicatorConfigMap())
                .thenReturn(
                        Map.of(
                                "X01", new ContraIndicatorConfig("X01", 4, -3, "1"),
                                "X02", new ContraIndicatorConfig("X02", 4, -3, "2"),
                                "Z03", new ContraIndicatorConfig("Z03", 4, -3, "3")));

        var mitigatedCi = createCi("X02");
        mitigatedCi.setMitigation(List.of(new Mitigation()));
        var contraIndicators = List.of(createCi("X01"), mitigatedCi, createCi("Z03"));

        // Act
        var userIdentity =
                userIdentityService.generateUserIdentity(
                        List.of(), "test-sub", Vot.P0, Vot.P2, contraIndicators);

        // Assert
        assertEquals(
                List.of(new ReturnCode("1"), new ReturnCode("2"), new ReturnCode("3")),
                userIdentity.getReturnCode());
    }

    @Test
    void generateUserIdentityShouldThrowWhenBreachingAndCiCodeNotFound() {
        // Arrange
        var emptyList = new ArrayList<VerifiableCredential>();
        when(mockConfigService.getParameter(CORE_VTM_CLAIM)).thenReturn("mock-vtm-claim");
        when(mockConfigService.getContraIndicatorConfigMap())
                .thenReturn(Map.of("X01", new ContraIndicatorConfig("X01", 4, -3, "1")));

        var contraIndicators = List.of(createCi("wat"));

        assertThrows(
                UnrecognisedCiException.class,
                () ->
                        userIdentityService.generateUserIdentity(
                                emptyList, "test-sub", Vot.P0, Vot.P2, contraIndicators));
    }

    @Test
    void generateUserIdentityShouldDeduplicateExitCodes() throws Exception {
        // Arrange
        mockParamStoreCalls(paramsToMockForP0);
        when(mockConfigService.getParameter(CI_SCORING_THRESHOLD, "P2")).thenReturn("0");
        when(mockConfigService.getContraIndicatorConfigMap())
                .thenReturn(
                        Map.of(
                                "X01", new ContraIndicatorConfig("X01", 4, -3, "1"),
                                "X02", new ContraIndicatorConfig("X02", 4, -3, "2"),
                                "Z03", new ContraIndicatorConfig("Z03", 4, -3, "3"),
                                "Z04", new ContraIndicatorConfig("Z04", 4, -3, "2")));

        var contraIndicators =
                List.of(createCi("X01"), createCi("X02"), createCi("Z03"), createCi("Z04"));

        // Act
        var userIdentity =
                userIdentityService.generateUserIdentity(
                        List.of(), "test-sub", Vot.P0, Vot.P2, contraIndicators);

        // Assert
        assertEquals(
                List.of(new ReturnCode("1"), new ReturnCode("2"), new ReturnCode("3")),
                userIdentity.getReturnCode());
    }

    @Test
    void generateUserIdentityShouldSetRequiredExitCodeWhenP0AndNotBreachingCiThreshold()
            throws Exception {
        // Arrange
        when(mockConfigService.getParameter(CORE_VTM_CLAIM)).thenReturn("mock-vtm-claim");
        when(mockConfigService.getParameter(CI_SCORING_THRESHOLD, "P2")).thenReturn("10");
        when(mockConfigService.getParameter(RETURN_CODES_NON_CI_BREACHING_P0)).thenReturn("🐧");

        when(mockConfigService.getContraIndicatorConfigMap())
                .thenReturn(Map.of("X01", new ContraIndicatorConfig("X01", 4, -3, "1")));

        var contraIndicators = List.of(createCi("X01"));

        // Act
        var userIdentity =
                userIdentityService.generateUserIdentity(
                        List.of(), "test-sub", Vot.P0, Vot.P2, contraIndicators);

        // Assert
        assertEquals(List.of(new ReturnCode("🐧")), userIdentity.getReturnCode());
        verify(mockConfigService, never()).getParameter(RETURN_CODES_ALWAYS_REQUIRED);
    }

    @Test
    void checkNamesForCorrelationValidateSpecialCharactersSuccessScenarios() {
        List<String> fullNames = List.of("Alice JANE DOE", "AlIce Ja-ne Do-e", "ALiCE JA'-ne Do'e");
        assertTrue(userIdentityService.checkNamesForCorrelation(fullNames));

        fullNames = List.of("SÖŞMİĞë", "sosmige", "SÖŞ-Mİ'Ğe");
        assertTrue(userIdentityService.checkNamesForCorrelation(fullNames));
    }

    @Test
    void checkNamesForCorrelationValidateSpecialCharactersFailScenarios() {
        List<String> fullNames = List.of("Alice JANE DOE", "Alce JANE DOE", "Alëce JANE DOE");
        assertFalse(userIdentityService.checkNamesForCorrelation(fullNames));

        fullNames = List.of("Alice JANE DOE", "Alce JANE DOE");
        assertFalse(userIdentityService.checkNamesForCorrelation(fullNames));

        fullNames = List.of("Alice JANE DOE", "JANE AlIce DOE");
        assertFalse(userIdentityService.checkNamesForCorrelation(fullNames));

        fullNames = List.of("Alice JANE DOE", "Alice JANE Onel");
        assertFalse(userIdentityService.checkNamesForCorrelation(fullNames));
    }

    @Test
    void getCredentialsWithSingleCredentialAndOnlyOneValidEvidence() {
        // Arrange
        var vcs = List.of(vcDcmawDrivingPermitDvaM1b());
        claimedIdentityConfig.setRequiresAdditionalEvidence(true);
        when(mockConfigService.getOauthCriActiveConnectionConfig(any()))
                .thenReturn(claimedIdentityConfig);

        // Act & Assert
        assertTrue(userIdentityService.checkRequiresAdditionalEvidence(vcs));
    }

    @Test
    void
            getCredentialsWithSingleCredentialWithOnlyOneValidEvidenceAndRequiresAdditionalEvidencesFalse() {
        // Arrange
        var vcs = List.of(vcDcmawDrivingPermitDvaM1b());
        claimedIdentityConfig.setRequiresAdditionalEvidence(false);
        when(mockConfigService.getOauthCriActiveConnectionConfig(any()))
                .thenReturn(claimedIdentityConfig);

        // Act & Assert
        assertFalse(userIdentityService.checkRequiresAdditionalEvidence(vcs));
    }

    @Test
    void getCredentialsWithMultipleCredentialsAndAllValidEvidence() {
        // Arrange
        var vcs = List.of(vcDcmawDrivingPermitDvaM1b(), vcF2fPassportPhotoM1a());

        // Act & Assert
        assertFalse(userIdentityService.checkRequiresAdditionalEvidence(vcs));
    }

    @Test
    void getCredentialsWithMultipleCredentialsAndAllInValidEvidence() {
        // Arrange
        var vcs = List.of(vcExperianFraudScoreOne(), vcExperianFraudScoreTwo());

        // Act & Assert
        assertFalse(userIdentityService.checkRequiresAdditionalEvidence(vcs));
    }

    @Test
    void getCredentialsWithMultipleCredentialsAndValidAndInValidEvidence() {
        // Arrange
        var vcs = List.of(vcDcmawDrivingPermitDvaM1b(), vcExperianFraudScoreTwo());

        claimedIdentityConfig.setRequiresAdditionalEvidence(true);
        when(mockConfigService.getOauthCriActiveConnectionConfig(any()))
                .thenReturn(claimedIdentityConfig);

        // Act & Assert
        assertTrue(userIdentityService.checkRequiresAdditionalEvidence(vcs));
    }

    @Test
    void shouldReturnCredentialsFromDataStoreForGPGProfile() throws Exception {
        var passportVc = vcWebPassportSuccessful();
        var fraudVc = vcExperianFraudScoreOne();
        var vcs = List.of(passportVc, fraudVc);

        mockParamStoreCalls(paramsToMockForP2);

        var credentials =
                userIdentityService.generateUserIdentity(
                        vcs, "test-sub", Vot.P2, Vot.P2, emptyContraIndicators);

        assertEquals(2, credentials.getVcs().size());
        assertEquals(passportVc.getVcString(), credentials.getVcs().get(0));
        assertEquals(fraudVc.getVcString(), credentials.getVcs().get(1));
        assertEquals("test-sub", credentials.getSub());

        IdentityClaim identityClaim = credentials.getIdentityClaim();
        assertEquals(GIVEN_NAME, identityClaim.getName().get(0).getNameParts().get(0).getType());
        assertEquals("KENNETH", identityClaim.getName().get(0).getNameParts().get(0).getValue());
        assertEquals("1965-07-08", identityClaim.getBirthDate().get(0).getValue());
    }

    @Test
    void shouldReturnCredentialsFromDataStoreForOperationalProfile() throws Exception {
        var hmrcVc = vcHmrcMigrationPCL200();
        var vcs = List.of(hmrcVc);

        var credentials =
                userIdentityService.generateUserIdentity(
                        vcs, "test-sub", Vot.PCL200, Vot.PCL200, emptyContraIndicators);

        assertEquals(1, credentials.getVcs().size());
        assertEquals(hmrcVc.getVcString(), credentials.getVcs().get(0));
        assertEquals("test-sub", credentials.getSub());

        IdentityClaim identityClaim = credentials.getIdentityClaim();
        assertEquals(GIVEN_NAME, identityClaim.getName().get(0).getNameParts().get(0).getType());
        assertEquals("KENNETH", identityClaim.getName().get(0).getNameParts().get(0).getValue());
        assertEquals("1965-07-08", identityClaim.getBirthDate().get(0).getValue());
    }

    @Test
    void areVCsCorrelatedReturnsTrueWhenVcAreCorrelatedJustForGPG45Profile() throws Exception {
        // Arrange
        var vcs =
                List.of(
                        generateVerifiableCredential(
                                USER_ID_1,
                                ADDRESS,
                                createCredentialWithNameAndBirthDate(
                                        "Jimbo", "Jones", "1000-01-01")),
                        generateVerifiableCredential(
                                USER_ID_1,
                                PASSPORT,
                                createCredentialWithNameAndBirthDate(
                                        "Jimbo", "Jones", "1000-01-01")),
                        generateVerifiableCredential(
                                USER_ID_1,
                                BAV,
                                createCredentialWithNameAndBirthDate(
                                        "Jimbo", "Jones", "1000-01-01")),
                        vcHmrcMigrationPCL200());

        // Act & Assert
        assertTrue(userIdentityService.areVcsCorrelated(vcs));
    }

    @Test
    void findIdentityReturnsIdentityClaimWhenEvidenceCheckIsFalse() throws Exception {
        var vcs = List.of(vcExperianFraudScoreTwo());
        Optional<IdentityClaim> result = userIdentityService.findIdentityClaim(vcs, false);
        assertTrue(result.isPresent());
        assertEquals("KENNETH DECERQUEIRA", result.get().getFullName());
    }

    @Test
    void findIdentityDoesNotReturnsIdentityClaimWhenEvidenceCheckIsTrue()
            throws HttpResponseExceptionWithErrorBody, CredentialParseException {
        var vcs = List.of(vcExperianFraudScoreOne());
        Optional<IdentityClaim> result = userIdentityService.findIdentityClaim(vcs, true);
        assertTrue(result.isEmpty());
    }

    @Test
    void findIdentityThrowsHttpResponseExceptionWithErrorBodyWhenNoNamePresent() {
        var vcs = List.of(vcExperianFraudMissingName());
        assertThrows(
                HttpResponseExceptionWithErrorBody.class,
                () -> userIdentityService.findIdentityClaim(vcs, false));
    }

    @Test
    void findIdentityReturnsIdentityClaimForOperationalVC() throws Exception {
        var vcs = List.of(vcHmrcMigrationPCL200());
        Optional<IdentityClaim> result = userIdentityService.findIdentityClaim(vcs);
        assertFalse(result.isEmpty());
    }

    @Test
    void findIdentityReturnsIdentityClaimForOperationalVcWithNoEvidence() throws Exception {
        var vcs = List.of(vcHmrcMigrationPCL250NoEvidence());
        Optional<IdentityClaim> result = userIdentityService.findIdentityClaim(vcs);
        assertFalse(result.isEmpty());
    }

    @Test
    void getUserClaimsForStoredIdentityShouldReturnListOfUserClaims() throws Exception {
        // Arrange
        var testVcs =
                List.of(
                        vcWebPassportSuccessful(),
                        vcWebDrivingPermitDvlaValid(),
                        vcNinoIdentityCheckSuccessful(),
                        vcExperianFraudScoreTwo(),
                        vcAddressOne());

        // Act
        var result = userIdentityService.getUserClaimsForStoredIdentity(Vot.P2, testVcs);

        // Assert
        assertEquals(5, result.size());
        // First element in the array is the identity claim
        assertEquals("KENNETH DECERQUEIRA", ((IdentityClaim) result.get(0)).getFullName());
        // Second element in the array is the address claim if it exists
        assertEquals("IDSWORTH ROAD", ((PostalAddress) result.get(1)).getStreetName());
        // Third element is the passport claim if it exists
        assertEquals("321654987", ((PassportDetails) result.get(2)).getDocumentNumber());
        // Fourth element is the driving permit claim if it exists
        assertEquals(
                "PARKE710112PBFGA", ((DrivingPermitDetails) result.get(3)).getPersonalNumber());
        // Fifth element if the nino claim if it exists
        assertEquals(
                "AA000003D", ((SocialSecurityRecordDetails) result.get(4)).getPersonalNumber());
    }

    @Test
    void getUserClaimsForStoredIdentityShouldFilterMissingClaims() throws Exception {
        // Arrange
        var testVcs = List.of(vcWebPassportSuccessful(), vcExperianFraudScoreTwo(), vcAddressOne());

        // Act
        var result = userIdentityService.getUserClaimsForStoredIdentity(Vot.P2, testVcs);

        // Assert
        assertEquals(3, result.size());
        // First element in the array is the identity claim
        assertEquals("KENNETH DECERQUEIRA", ((IdentityClaim) result.get(0)).getFullName());
        // Second element in the array is the address claim if it exists
        assertEquals("IDSWORTH ROAD", ((PostalAddress) result.get(1)).getStreetName());
        // Third element is the passport claim if it exists
        assertEquals("321654987", ((PassportDetails) result.get(2)).getDocumentNumber());
    }

    @Nested
    class AreNamesAndDobCorrelatedForReverification {
        @BeforeEach
        void setup() {
            when(mockConfigService.getParameter(COI_CHECK_GIVEN_NAME_CHARS)).thenReturn("1");
            when(mockConfigService.getParameter(COI_CHECK_FAMILY_NAME_CHARS)).thenReturn("3");
        }

        @Test
        void shouldReturnTrueWhenAllNamesAndDobMatchExactly() throws Exception {
            // Arrange
            var vcs =
                    List.of(
                            generateVerifiableCredential(
                                    USER_ID_1,
                                    ADDRESS,
                                    createCredentialWithNameAndBirthDate(
                                            "Jimbo", "Jones", "1000-01-01")),
                            generateVerifiableCredential(
                                    USER_ID_1,
                                    PASSPORT,
                                    createCredentialWithNameAndBirthDate(
                                            "Jimbo", "Jones", "1000-01-01")),
                            generateVerifiableCredential(
                                    USER_ID_1,
                                    BAV,
                                    createCredentialWithNameAndBirthDate(
                                            "Jimbo", "Jones", "1000-01-01")),
                            vcHmrcMigrationPCL200());

            // Act & Assert
            assertTrue(userIdentityService.areNamesAndDobCorrelatedForReverification(vcs));
        }

        @Test
        void shouldReturnTrueWhenFamilyNamesAreDifferentButMatchWithinCharAllowance()
                throws Exception {
            // Arrange
            var vcs =
                    List.of(
                            generateVerifiableCredential(
                                    USER_ID_1,
                                    PASSPORT,
                                    createCredentialWithNameAndBirthDate(
                                            "Jimbo", "Jonathon", "1000-01-01")),
                            generateVerifiableCredential(
                                    USER_ID_1,
                                    BAV,
                                    createCredentialWithNameAndBirthDate(
                                            "Jimbo", "Jonas", "1000-01-01")));

            // Act & Assert
            assertTrue(userIdentityService.areNamesAndDobCorrelatedForReverification(vcs));
        }

        @Test
        void shouldReturnTrueWhenGivenNamesAreDifferentButMatchWithinCharAllowance()
                throws Exception {
            // Arrange
            var vcs =
                    List.of(
                            generateVerifiableCredential(
                                    USER_ID_1,
                                    PASSPORT,
                                    createCredentialWithNameAndBirthDate(
                                            "Jimbo", "Jones", "1000-01-01")),
                            generateVerifiableCredential(
                                    USER_ID_1,
                                    BAV,
                                    createCredentialWithNameAndBirthDate(
                                            "Jamie", "Jones", "1000-01-01")));

            // Act & Assert
            assertTrue(userIdentityService.areNamesAndDobCorrelatedForReverification(vcs));
        }

        @Test
        void shouldReturnFalseWhenDobDoNotMatch() throws Exception {
            // Arrange
            var vcs =
                    List.of(
                            generateVerifiableCredential(
                                    USER_ID_1,
                                    PASSPORT,
                                    createCredentialWithNameAndBirthDate(
                                            "Jimbo", "Jones", "2000-01-01")),
                            generateVerifiableCredential(
                                    USER_ID_1,
                                    BAV,
                                    createCredentialWithNameAndBirthDate(
                                            "Jimbo", "Jones", "1000-01-01")));

            // Act & Assert
            assertFalse(userIdentityService.areNamesAndDobCorrelatedForReverification(vcs));
        }

        @Test
        void shouldReturnFalseWhenFamilyNamesDoNotMatchWithinAllowance() throws Exception {
            // Arrange
            var vcs =
                    List.of(
                            generateVerifiableCredential(
                                    USER_ID_1,
                                    PASSPORT,
                                    createCredentialWithNameAndBirthDate(
                                            "Jimbo", "Jones", "1000-01-01")),
                            generateVerifiableCredential(
                                    USER_ID_1,
                                    BAV,
                                    createCredentialWithNameAndBirthDate(
                                            "Jimbo", "Jared", "1000-01-01")));

            // Act & Assert
            assertFalse(userIdentityService.areNamesAndDobCorrelatedForReverification(vcs));
        }

        @Test
        void shouldReturnFalseWhenGivenNamesDoNotMatchWithinAllowance() throws Exception {
            // Arrange
            var vcs =
                    List.of(
                            generateVerifiableCredential(
                                    USER_ID_1,
                                    PASSPORT,
                                    createCredentialWithNameAndBirthDate(
                                            "Jimbo", "Jones", "1000-01-01")),
                            generateVerifiableCredential(
                                    USER_ID_1,
                                    BAV,
                                    createCredentialWithNameAndBirthDate(
                                            "Timbo", "Jones", "1000-01-01")));

            // Act & Assert
            assertFalse(userIdentityService.areNamesAndDobCorrelatedForReverification(vcs));
        }
    }

    private void mockParamStoreCalls(Map<ConfigurationVariable, String> params) {
        params.forEach((key, value) -> when(mockConfigService.getParameter(key)).thenReturn(value));
    }

    private IdentityCheckCredential createCredentialWithNameAndBirthDate(
            String givenName, String familyName, String birthDate) {
        var birthDateList = new ArrayList<String>();
        birthDateList.add(birthDate);
        return createCredentialWithNameAndBirthDate(
                givenName, null, familyName, birthDateList, true);
    }

    private IdentityCheckCredential createCredentialWithNameAndBirthDate(
            String givenName, String middleName, String familyName, String birthDate) {
        var birthDateList = new ArrayList<String>();
        birthDateList.add(birthDate);
        return createCredentialWithNameAndBirthDate(
                givenName, middleName, familyName, birthDateList, true);
    }

    private IdentityCheckCredential createCredentialWithNameAndBirthDate(
            String givenName, String familyName, String birthDate, boolean isSuccessful) {
        var birthDateList = new ArrayList<String>();
        birthDateList.add(birthDate);
        return createCredentialWithNameAndBirthDate(
                givenName, null, familyName, birthDateList, isSuccessful);
    }

    private IdentityCheckCredential createCredentialWithNameAndBirthDate(
            String givenName, String familyName, List<String> birthDates) {
        return createCredentialWithNameAndBirthDate(givenName, null, familyName, birthDates, true);
    }

    private static IdentityCheckCredential createCredentialWithNameAndBirthDate(
            String givenName,
            String middleName,
            String familyName,
            List<String> birthDates,
            boolean isSuccessful) {
        var nameParts =
                new ArrayList<>(
                        List.of(
                                createNamePart(givenName, GIVEN_NAME),
                                createNamePart(familyName, FAMILY_NAME)));
        if (middleName != null) {
            nameParts.add(1, createNamePart(middleName, GIVEN_NAME));
        }

        return IdentityCheckCredential.builder()
                .withType(
                        List.of(
                                VerifiableCredentialType.VERIFIABLE_CREDENTIAL,
                                VerifiableCredentialType.IDENTITY_CHECK_CREDENTIAL))
                .withCredentialSubject(
                        IdentityCheckSubject.builder()
                                .withName(List.of(Name.builder().withNameParts(nameParts).build()))
                                .withBirthDate(
                                        birthDates.stream()
                                                .map(BirthDateGenerator::createBirthDate)
                                                .toList())
                                .build())
                .withEvidence(
                        List.of(
                                IdentityCheck.builder()
                                        .withType(IdentityCheck.IdentityCheckType.IDENTITY_CHECK_)
                                        .withTxn("1c04edf0-a205-4585-8877-be6bd1776a39")
                                        .withStrengthScore(isSuccessful ? 4 : 0)
                                        .withValidityScore(isSuccessful ? 2 : 0)
                                        .withCheckDetails(
                                                List.of(
                                                        CheckDetails.builder()
                                                                .withCheckMethod(
                                                                        CheckDetails.CheckMethodType
                                                                                .DATA)
                                                                .withDataCheck(
                                                                        CheckDetails.DataCheckType
                                                                                .CANCELLED_CHECK)
                                                                .build(),
                                                        CheckDetails.builder()
                                                                .withCheckMethod(
                                                                        CheckDetails.CheckMethodType
                                                                                .DATA)
                                                                .withDataCheck(
                                                                        CheckDetails.DataCheckType
                                                                                .RECORD_CHECK)
                                                                .build()))
                                        .build()))
                .build();
    }

    private static ContraIndicator createCi(String code) {
        var ci = new ContraIndicator();
        ci.setCode(code);
        return ci;
    }
}
