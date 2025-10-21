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
import uk.gov.di.ipv.core.library.config.domain.CoiConfig;
import uk.gov.di.ipv.core.library.config.domain.Config;
import uk.gov.di.ipv.core.library.config.domain.InternalOperationsConfig;
import uk.gov.di.ipv.core.library.config.domain.VotCiThresholdsConfig;
import uk.gov.di.ipv.core.library.domain.ContraIndicatorConfig;
import uk.gov.di.ipv.core.library.domain.ErrorResponse;
import uk.gov.di.ipv.core.library.domain.IdentityClaim;
import uk.gov.di.ipv.core.library.domain.ReturnCode;
import uk.gov.di.ipv.core.library.domain.VerifiableCredential;
import uk.gov.di.ipv.core.library.dto.OauthCriConfig;
import uk.gov.di.ipv.core.library.enums.Vot;
import uk.gov.di.ipv.core.library.exceptions.HttpResponseExceptionWithErrorBody;
import uk.gov.di.ipv.core.library.exceptions.UnrecognisedCiException;
import uk.gov.di.ipv.core.library.helpers.vocab.BirthDateGenerator;
import uk.gov.di.ipv.core.library.service.ConfigService;
import uk.gov.di.model.AddressAssertion;
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
import static org.mockito.Mockito.when;
import static org.mockito.quality.Strictness.LENIENT;
import static uk.gov.di.ipv.core.library.domain.Cri.ADDRESS;
import static uk.gov.di.ipv.core.library.domain.Cri.BAV;
import static uk.gov.di.ipv.core.library.domain.Cri.DCMAW;
import static uk.gov.di.ipv.core.library.domain.Cri.EXPERIAN_FRAUD;
import static uk.gov.di.ipv.core.library.domain.Cri.PASSPORT;
import static uk.gov.di.ipv.core.library.fixtures.VcFixtures.vcAddressEmpty;
import static uk.gov.di.ipv.core.library.fixtures.VcFixtures.vcAddressNoCredentialSubject;
import static uk.gov.di.ipv.core.library.fixtures.VcFixtures.vcAddressOne;
import static uk.gov.di.ipv.core.library.fixtures.VcFixtures.vcAddressTwo;
import static uk.gov.di.ipv.core.library.fixtures.VcFixtures.vcDcmawDrivingPermitDvaM1b;
import static uk.gov.di.ipv.core.library.fixtures.VcFixtures.vcDcmawPassport;
import static uk.gov.di.ipv.core.library.fixtures.VcFixtures.vcExperianFraudMissingName;
import static uk.gov.di.ipv.core.library.fixtures.VcFixtures.vcExperianFraudScoreOne;
import static uk.gov.di.ipv.core.library.fixtures.VcFixtures.vcExperianFraudScoreTwo;
import static uk.gov.di.ipv.core.library.fixtures.VcFixtures.vcF2fDrivingPermitDvaPhotoM1a;
import static uk.gov.di.ipv.core.library.fixtures.VcFixtures.vcF2fPassportPhotoM1a;
import static uk.gov.di.ipv.core.library.fixtures.VcFixtures.vcInvalidVot;
import static uk.gov.di.ipv.core.library.fixtures.VcFixtures.vcNinoIdentityCheckEmptySocialSecurityRecord;
import static uk.gov.di.ipv.core.library.fixtures.VcFixtures.vcNinoIdentityCheckMissingSocialSecurityRecord;
import static uk.gov.di.ipv.core.library.fixtures.VcFixtures.vcNinoIdentityCheckSuccessful;
import static uk.gov.di.ipv.core.library.fixtures.VcFixtures.vcNinoIdentityCheckUnsuccessful;
import static uk.gov.di.ipv.core.library.fixtures.VcFixtures.vcNinoInvalidVcType;
import static uk.gov.di.ipv.core.library.fixtures.VcFixtures.vcP2Vot;
import static uk.gov.di.ipv.core.library.fixtures.VcFixtures.vcWebDrivingPermitDvaValid;
import static uk.gov.di.ipv.core.library.fixtures.VcFixtures.vcWebDrivingPermitDvlaValid;
import static uk.gov.di.ipv.core.library.fixtures.VcFixtures.vcWebDrivingPermitEmptyDrivingPermit;
import static uk.gov.di.ipv.core.library.fixtures.VcFixtures.vcWebDrivingPermitFailedChecks;
import static uk.gov.di.ipv.core.library.fixtures.VcFixtures.vcWebDrivingPermitIncorrectType;
import static uk.gov.di.ipv.core.library.fixtures.VcFixtures.vcWebDrivingPermitMissingDrivingPermit;
import static uk.gov.di.ipv.core.library.fixtures.VcFixtures.vcWebPassportClaimInvalidType;
import static uk.gov.di.ipv.core.library.fixtures.VcFixtures.vcWebPassportEmptyPassportDetails;
import static uk.gov.di.ipv.core.library.fixtures.VcFixtures.vcWebPassportMissingBirthDate;
import static uk.gov.di.ipv.core.library.fixtures.VcFixtures.vcWebPassportMissingName;
import static uk.gov.di.ipv.core.library.fixtures.VcFixtures.vcWebPassportMissingPassportDetails;
import static uk.gov.di.ipv.core.library.fixtures.VcFixtures.vcWebPassportSuccessful;
import static uk.gov.di.ipv.core.library.helpers.VerifiableCredentialGenerator.generateVerifiableCredential;
import static uk.gov.di.ipv.core.library.helpers.vocab.NameGenerator.NamePartGenerator.createNamePart;
import static uk.gov.di.model.NamePart.NamePartType.FAMILY_NAME;
import static uk.gov.di.model.NamePart.NamePartType.GIVEN_NAME;

@ExtendWith(MockitoExtension.class)
@MockitoSettings(strictness = Strictness.LENIENT)
class UserIdentityServiceTest {
    private static final String USER_ID_1 = "user-id-1";

    private final List<ContraIndicator> emptyContraIndicators = List.of();

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
                        .componentId("https://review-a.integration.account.gov.uk")
                        .clientCallbackUrl(new URI("http://example.com/redirect"))
                        .requiresApiKey(true)
                        .requiresAdditionalEvidence(false)
                        .build();
    }

    @Mock private Config mockConfig;
    @Mock private InternalOperationsConfig mockSelf;
    @Mock private CoiConfig mockCoi;
    @Mock private VotCiThresholdsConfig mockThresholds;
    private final Map<String, String> returnCodes = new java.util.HashMap<>();

    @BeforeEach
    void wireConfig() {
        when(mockConfigService.getConfiguration()).thenReturn(mockConfig);
        when(mockConfig.getSelf()).thenReturn(mockSelf);
        when(mockSelf.getCoi()).thenReturn(mockCoi);
        when(mockSelf.getCiScoringThresholdByVot()).thenReturn(mockThresholds);

        when(mockSelf.getCoreVtmClaim()).thenReturn(URI.create("mock-vtm-claim"));

        when(mockCoi.getFamilyNameChars()).thenReturn(5);
        when(mockCoi.getGivenNameChars()).thenReturn(1);
        when(mockThresholds.getP2()).thenReturn(10);

        returnCodes.clear();
        returnCodes.put("alwaysRequired", "");
        returnCodes.put("nonCiBreachingP0", "");
        when(mockSelf.getReturnCodes()).thenReturn(returnCodes);
    }

    private void setP2Threshold(int value) {
        when(mockThresholds.getP2()).thenReturn(value);
    }

    private void setReturnCodes(Map<String, String> map) {
        returnCodes.clear();
        returnCodes.put("alwaysRequired", "");
        returnCodes.put("nonCiBreachingP0", "");
        returnCodes.putAll(map);
    }

    private void setFamilyNameChars(int v) {
        when(mockCoi.getFamilyNameChars()).thenReturn(v);
    }

    private void setGivenNameChars(int v) {
        when(mockCoi.getGivenNameChars()).thenReturn(v);
    }

    @Test
    void shouldReturnCredentialsFromDataStore() throws Exception {
        // Arrange
        var passportVc = vcWebPassportSuccessful();
        var fraudVc = vcWebPassportSuccessful();
        var vcs = List.of(passportVc, fraudVc);

        useP2Defaults();

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

        useP2Defaults();

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
    void areVCsCorrelatedReturnFalseWhenNamesConcatenateToTheSameString() throws Exception {
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
                                        "Jimb", "oJones", "1000-01-01")));

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
            setFamilyNameChars(5);
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
            setFamilyNameChars(500);
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

        useP2Defaults();

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

        useP2Defaults();

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

        useP0NonCiCode("🐧");
        setP2Threshold(0);

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
        var vc = vcP2Vot();

        // Act
        var vot = userIdentityService.getVot(vc);

        // Assert
        assertEquals(Vot.P2, vot);
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
        useP2Defaults();

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
        useP2Defaults();

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

        useP0NonCiCode("🐧");
        setP2Threshold(0);

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

        useP2Defaults();

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

        useP2Defaults();

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
        useP2Defaults();

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

        useP0NonCiCode("🐧");
        setP2Threshold(0);

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

        useP2Defaults();

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

        useP2Defaults();

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

        useP2Defaults();

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

        useP2Defaults();

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

        useP2Defaults();

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
        useP2Defaults();

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
        useP2Defaults();

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

        useP2Defaults();

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

        useP0NonCiCode("🐧");
        setP2Threshold(0);

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

        useP2Defaults();

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

        useP2Defaults();

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

        useP0NonCiCode("🐧");
        setP2Threshold(0);

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

        useP2Defaults();

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

        useP2Defaults();

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

        useP2Defaults();

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

        useP2Defaults();

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

        useP2Defaults();

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
        useP2Defaults();
        setReturnCodes(Map.of("alwaysRequired", "🦆,🐧"));
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
        useP2Defaults();

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
        useP0NonCiCode("🐧");
        setP2Threshold(0);
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
        useP0NonCiCode("🐧");
        setP2Threshold(0);
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
        setP2Threshold(10); // if code uses getP2()
        when(mockThresholds.getThreshold("P2")).thenReturn(10);
        when(mockThresholds.getThreshold("P0")).thenReturn(10);

        setReturnCodes(
                Map.of(
                        "nonCiBreachingP0", "🐧",
                        "alwaysRequired", "🦆"));

        when(mockConfigService.getContraIndicatorConfigMap())
                .thenReturn(Map.of("X01", new ContraIndicatorConfig("X01", 4, -3, "1")));

        var contraIndicators = List.of(createCi("X01"));

        // Act
        var userIdentity =
                userIdentityService.generateUserIdentity(
                        List.of(), "test-sub", Vot.P0, Vot.P2, contraIndicators);

        // Assert
        assertEquals(List.of(new ReturnCode("🐧")), userIdentity.getReturnCode());
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

        useP2Defaults();

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
    void findIdentityReturnsIdentityClaimWhenEvidenceCheckIsFalse() throws Exception {
        var vcs = List.of(vcExperianFraudScoreTwo());
        Optional<IdentityClaim> result = userIdentityService.findIdentityClaim(vcs, false);
        assertTrue(result.isPresent());
        assertEquals("KENNETH DECERQUEIRA", result.get().getFullName());
    }

    @Test
    void findIdentityDoesNotReturnsIdentityClaimWhenEvidenceCheckIsTrue()
            throws HttpResponseExceptionWithErrorBody {
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
    void findIdentityReturnsIdentityClaim() throws Exception {
        var vcs = List.of(vcDcmawPassport());
        Optional<IdentityClaim> result = userIdentityService.findIdentityClaim(vcs);
        assertTrue(result.isPresent());
    }

    @Test
    void getUserClaimsShouldReturnListOfUserClaims() throws Exception {
        // Arrange
        var drivingPermitVc = vcWebDrivingPermitDvlaValid();
        var testVcs =
                List.of(
                        vcWebPassportSuccessful(),
                        vcWebDrivingPermitDvlaValid(),
                        vcNinoIdentityCheckSuccessful(),
                        vcExperianFraudScoreTwo(),
                        vcAddressOne());

        // Act
        var result = userIdentityService.getUserClaims(testVcs);

        // Assert
        assertEquals(
                ((IdentityCheckSubject)
                                vcWebPassportSuccessful().getCredential().getCredentialSubject())
                        .getName(),
                result.getIdentityClaim().getName());
        assertEquals(
                ((IdentityCheckSubject)
                                vcWebPassportSuccessful().getCredential().getCredentialSubject())
                        .getBirthDate(),
                result.getIdentityClaim().getBirthDate());
        assertEquals(
                ((IdentityCheckSubject)
                                vcWebPassportSuccessful().getCredential().getCredentialSubject())
                        .getPassport(),
                result.getPassportClaim());
        assertEquals(
                ((IdentityCheckSubject) drivingPermitVc.getCredential().getCredentialSubject())
                        .getDrivingPermit()
                        .get(0)
                        .getPersonalNumber(),
                result.getDrivingPermitClaim().get(0).getPersonalNumber());
        assertEquals(
                ((IdentityCheckSubject)
                                vcNinoIdentityCheckSuccessful()
                                        .getCredential()
                                        .getCredentialSubject())
                        .getSocialSecurityRecord(),
                result.getNinoClaim());
        assertEquals(
                ((AddressAssertion) vcAddressOne().getCredential().getCredentialSubject())
                        .getAddress(),
                result.getAddressClaim());
    }

    @Nested
    class AreNamesAndDobCorrelatedForReverification {
        @BeforeEach
        void setup() {
            setGivenNameChars(1);
            setFamilyNameChars(3);
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
                                            "Jimbo", "Jones", "1000-01-01")));

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

    private void useP2Defaults() {
        when(mockConfigService.getCoreVtmClaim()).thenReturn("mock-vtm-claim");
        returnCodes.put("nonCiBreachingP0", "");
        when(mockSelf.getReturnCodes()).thenReturn(returnCodes);
    }

    private void useP0NonCiCode(String code) {
        when(mockConfigService.getCoreVtmClaim()).thenReturn("mock-vtm-claim");
        returnCodes.put("nonCiBreachingP0", code);
        when(mockSelf.getReturnCodes()).thenReturn(returnCodes);
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
