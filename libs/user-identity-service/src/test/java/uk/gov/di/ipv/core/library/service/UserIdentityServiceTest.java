package uk.gov.di.ipv.core.library.service;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.nimbusds.jose.JOSEObjectType;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.crypto.ECDSASigner;
import com.nimbusds.jose.jwk.ECKey;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.NullAndEmptySource;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import uk.gov.di.ipv.core.library.config.ConfigurationVariable;
import uk.gov.di.ipv.core.library.domain.BirthDate;
import uk.gov.di.ipv.core.library.domain.ContraIndicatorConfig;
import uk.gov.di.ipv.core.library.domain.ContraIndicators;
import uk.gov.di.ipv.core.library.domain.ErrorResponse;
import uk.gov.di.ipv.core.library.domain.IdentityClaim;
import uk.gov.di.ipv.core.library.domain.Name;
import uk.gov.di.ipv.core.library.domain.NameParts;
import uk.gov.di.ipv.core.library.domain.ReturnCode;
import uk.gov.di.ipv.core.library.domain.VerifiableCredential;
import uk.gov.di.ipv.core.library.domain.cimitvc.ContraIndicator;
import uk.gov.di.ipv.core.library.domain.cimitvc.Mitigation;
import uk.gov.di.ipv.core.library.dto.OauthCriConfig;
import uk.gov.di.ipv.core.library.dto.VcStatusDto;
import uk.gov.di.ipv.core.library.enums.Vot;
import uk.gov.di.ipv.core.library.exceptions.CredentialParseException;
import uk.gov.di.ipv.core.library.exceptions.HttpResponseExceptionWithErrorBody;
import uk.gov.di.ipv.core.library.exceptions.NoVcStatusForIssuerException;
import uk.gov.di.ipv.core.library.exceptions.UnrecognisedCiException;
import uk.gov.di.ipv.core.library.fixtures.TestFixtures;
import uk.gov.di.ipv.core.library.persistence.DataStore;
import uk.gov.di.ipv.core.library.persistence.item.VcStoreItem;

import java.net.URI;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;
import static uk.gov.di.ipv.core.library.config.ConfigurationVariable.CI_SCORING_THRESHOLD;
import static uk.gov.di.ipv.core.library.config.ConfigurationVariable.CORE_VTM_CLAIM;
import static uk.gov.di.ipv.core.library.config.ConfigurationVariable.RETURN_CODES_ALWAYS_REQUIRED;
import static uk.gov.di.ipv.core.library.config.ConfigurationVariable.RETURN_CODES_NON_CI_BREACHING_P0;
import static uk.gov.di.ipv.core.library.domain.CriConstants.ADDRESS_CRI;
import static uk.gov.di.ipv.core.library.domain.CriConstants.BAV_CRI;
import static uk.gov.di.ipv.core.library.domain.CriConstants.DCMAW_CRI;
import static uk.gov.di.ipv.core.library.domain.CriConstants.EXPERIAN_FRAUD_CRI;
import static uk.gov.di.ipv.core.library.domain.CriConstants.NON_EVIDENCE_CRI_TYPES;
import static uk.gov.di.ipv.core.library.domain.CriConstants.PASSPORT_CRI;
import static uk.gov.di.ipv.core.library.domain.VerifiableCredentialConstants.VC_BIRTH_DATE;
import static uk.gov.di.ipv.core.library.domain.VerifiableCredentialConstants.VC_CLAIM;
import static uk.gov.di.ipv.core.library.domain.VerifiableCredentialConstants.VC_CREDENTIAL_SUBJECT;
import static uk.gov.di.ipv.core.library.domain.VerifiableCredentialConstants.VC_FAMILY_NAME;
import static uk.gov.di.ipv.core.library.domain.VerifiableCredentialConstants.VC_GIVEN_NAME;
import static uk.gov.di.ipv.core.library.domain.VerifiableCredentialConstants.VC_NAME;
import static uk.gov.di.ipv.core.library.domain.VocabConstants.ADDRESS_CLAIM_NAME;
import static uk.gov.di.ipv.core.library.fixtures.TestFixtures.EC_PRIVATE_KEY_JWK;
import static uk.gov.di.ipv.core.library.fixtures.VcFixtures.*;
import static uk.gov.di.ipv.core.library.fixtures.VcFixtures.PASSPORT_NON_DCMAW_SUCCESSFUL_VC;
import static uk.gov.di.ipv.core.library.fixtures.VcFixtures.vcExperianFraudMissingName;
import static uk.gov.di.ipv.core.library.fixtures.VcFixtures.vcExperianFraudScoreOne;
import static uk.gov.di.ipv.core.library.fixtures.VcFixtures.vcHmrcMigration;

@ExtendWith(MockitoExtension.class)
class UserIdentityServiceTest {
    public static final JWSHeader JWS_HEADER =
            new JWSHeader.Builder(JWSAlgorithm.ES256).type(JOSEObjectType.JWT).build();
    private static final String USER_ID_1 = "user-id-1";
    private static final ObjectMapper objectMapper = new ObjectMapper();
    private static ECDSASigner jwtSigner;
    @Mock private ConfigService mockConfigService;
    @Mock private DataStore<VcStoreItem> mockDataStore;
    private final ContraIndicators emptyContraIndicators =
            ContraIndicators.builder().usersContraIndicators(List.of()).build();
    private UserIdentityService userIdentityService;
    private final Map<ConfigurationVariable, String> paramsToMockForP2 =
            Map.of(CORE_VTM_CLAIM, "mock-vtm-claim");
    private final Map<ConfigurationVariable, String> paramsToMockForP0 =
            Map.of(CORE_VTM_CLAIM, "mock-vtm-claim", CI_SCORING_THRESHOLD, "0");
    private final Map<ConfigurationVariable, String> paramsToMockForP0WithNoCi =
            Map.of(
                    CORE_VTM_CLAIM,
                    "mock-vtm-claim",
                    CI_SCORING_THRESHOLD,
                    "0",
                    RETURN_CODES_NON_CI_BREACHING_P0,
                    "🐧");
    public static OauthCriConfig claimedIdentityConfig;

    @BeforeAll
    static void beforeAllSetUp() throws Exception {
        jwtSigner = new ECDSASigner(ECKey.parse(EC_PRIVATE_KEY_JWK).toECPrivateKey());
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

    @BeforeEach
    void setUp() {
        userIdentityService = new UserIdentityService(mockConfigService);
    }

    @Test
    void shouldReturnCredentialsFromDataStore() throws Exception {
        // Arrange
        var passportVc = PASSPORT_NON_DCMAW_SUCCESSFUL_VC;
        var fraudVc = PASSPORT_NON_DCMAW_SUCCESSFUL_VC;
        var vcs = List.of(passportVc, fraudVc);

        mockParamStoreCalls(paramsToMockForP2);
        mockCredentialIssuerConfig();

        // Act
        var credentials =
                userIdentityService.generateUserIdentity(
                        vcs, "test-sub", Vot.P2, emptyContraIndicators);

        // Assert
        assertEquals(passportVc.getVcString(), credentials.getVcs().get(0));
        assertEquals(fraudVc.getVcString(), credentials.getVcs().get(1));
        assertEquals("test-sub", credentials.getSub());
    }

    @Test
    void shouldSetVotClaimToP2OnSuccessfulIdentityCheck() throws Exception {
        // Arrange
        var vcs =
                List.of(
                        PASSPORT_NON_DCMAW_SUCCESSFUL_VC,
                        vcExperianFraudScoreOne(),
                        vcExperianFraudScoreTwo(),
                        VC_ADDRESS);

        mockParamStoreCalls(paramsToMockForP2);
        mockCredentialIssuerConfig();

        // Act
        var credentials =
                userIdentityService.generateUserIdentity(
                        vcs, "test-sub", Vot.P2, emptyContraIndicators);

        // Assert
        assertEquals(Vot.P2, credentials.getVot());
    }

    @Test
    void areVCsCorrelatedReturnsTrueWhenVcAreCorrelated() throws Exception {
        // Arrange
        var vcs =
                List.of(
                        TestFixtures.createVerifiableCredential(
                                USER_ID_1,
                                ADDRESS_CRI,
                                createCredentialWithNameAndBirthDate(
                                        "Jimbo", "Jones", "1000-01-01")),
                        TestFixtures.createVerifiableCredential(
                                USER_ID_1,
                                PASSPORT_CRI,
                                createCredentialWithNameAndBirthDate(
                                        "Jimbo", "Jones", "1000-01-01")),
                        TestFixtures.createVerifiableCredential(
                                USER_ID_1,
                                BAV_CRI,
                                createCredentialWithNameAndBirthDate(
                                        "Jimbo", "Jones", "1000-01-01")),
                        vcTicf());
        mockCredentialIssuerConfig();

        // Act & Assert
        assertTrue(userIdentityService.areVcsCorrelated(vcs));
    }

    @Test
    void areVCsCorrelatedReturnFalseWhenNamesDiffer() throws Exception {
        // Arrange
        var vcs =
                List.of(
                        TestFixtures.createVerifiableCredential(
                                USER_ID_1,
                                ADDRESS_CRI,
                                createCredentialWithNameAndBirthDate(
                                        "Jimbo", "Jones", "1000-01-01")),
                        TestFixtures.createVerifiableCredential(
                                USER_ID_1,
                                PASSPORT_CRI,
                                createCredentialWithNameAndBirthDate(
                                        "Corky", "Jones", "1000-01-01")),
                        TestFixtures.createVerifiableCredential(
                                USER_ID_1,
                                EXPERIAN_FRAUD_CRI,
                                createCredentialWithNameAndBirthDate(
                                        "Jimbo", "Jones", "1000-01-01")),
                        vcTicf());
        mockCredentialIssuerConfig();

        // Act & Assert
        assertFalse(userIdentityService.areVcsCorrelated(vcs));
    }

    @Test
    void areVCsCorrelatedReturnFalseWhenNameDifferentForBavCRI() throws Exception {
        // Arrange
        var vcs =
                List.of(
                        TestFixtures.createVerifiableCredential(
                                USER_ID_1,
                                DCMAW_CRI,
                                createCredentialWithNameAndBirthDate(
                                        "Jimbo", "Jones", "1000-01-01")),
                        TestFixtures.createVerifiableCredential(
                                USER_ID_1,
                                BAV_CRI,
                                createCredentialWithNameAndBirthDate(
                                        "Jimmy", "Jones",
                                        ""))); // BAV cri doesn't provide birthdate
        mockCredentialIssuerConfig();

        // Act & Assert
        assertFalse(userIdentityService.areVcsCorrelated(vcs));
    }

    @ParameterizedTest
    @NullAndEmptySource
    void areVCsCorrelatedShouldThrowExceptionWhenVcHasMissingGivenName(String missingName)
            throws Exception {
        // Arrange
        var vcs =
                List.of(
                        TestFixtures.createVerifiableCredential(
                                USER_ID_1,
                                PASSPORT_CRI,
                                createCredentialWithNameAndBirthDate(
                                        "Jimbo", "Jones", "1000-01-01")),
                        TestFixtures.createVerifiableCredential(
                                USER_ID_1,
                                EXPERIAN_FRAUD_CRI,
                                createCredentialWithNameAndBirthDate(
                                        missingName, "Jones", "1000-01-01")));
        mockCredentialIssuerConfig();

        // Act & Assert
        HttpResponseExceptionWithErrorBody thrownError =
                assertThrows(
                        HttpResponseExceptionWithErrorBody.class,
                        () -> userIdentityService.areVcsCorrelated(vcs));

        assertEquals(500, thrownError.getResponseCode());
        assertEquals(
                ErrorResponse.FAILED_NAME_CORRELATION.getCode(),
                thrownError.getErrorBody().get("error"));
        assertEquals(
                ErrorResponse.FAILED_NAME_CORRELATION.getMessage(),
                thrownError.getErrorBody().get("error_description"));
    }

    @ParameterizedTest
    @NullAndEmptySource
    void areVCsCorrelatedShouldThrowExceptionWhenVcHasMissingFamilyName(String missingName)
            throws Exception {
        // Arrange
        var vcs =
                List.of(
                        TestFixtures.createVerifiableCredential(
                                USER_ID_1,
                                PASSPORT_CRI,
                                createCredentialWithNameAndBirthDate(
                                        "Jimbo", missingName, "1000-01-01")),
                        TestFixtures.createVerifiableCredential(
                                USER_ID_1,
                                EXPERIAN_FRAUD_CRI,
                                createCredentialWithNameAndBirthDate(
                                        "Jimbo", "Jones", "1000-01-01")));
        mockCredentialIssuerConfig();

        // Act & Assert
        HttpResponseExceptionWithErrorBody thrownError =
                assertThrows(
                        HttpResponseExceptionWithErrorBody.class,
                        () -> userIdentityService.areVcsCorrelated(vcs));

        assertEquals(500, thrownError.getResponseCode());
        assertEquals(
                ErrorResponse.FAILED_NAME_CORRELATION.getCode(),
                thrownError.getErrorBody().get("error"));
        assertEquals(
                ErrorResponse.FAILED_NAME_CORRELATION.getMessage(),
                thrownError.getErrorBody().get("error_description"));
    }

    @ParameterizedTest
    @NullAndEmptySource
    void areVCsCorrelatedShouldReturnTrueWhenAddressVcHasMissingName(String missing)
            throws Exception {
        // Arrange
        var vcs =
                List.of(
                        TestFixtures.createVerifiableCredential(
                                USER_ID_1,
                                EXPERIAN_FRAUD_CRI,
                                createCredentialWithNameAndBirthDate(
                                        "Jimbo", "Jones", "1000-01-01")),
                        TestFixtures.createVerifiableCredential(
                                USER_ID_1,
                                ADDRESS_CRI,
                                createCredentialWithNameAndBirthDate(
                                        missing, missing, "1000-01-01")));
        mockCredentialIssuerConfig();

        // Act & Assert
        assertTrue(userIdentityService.areVcsCorrelated(vcs));
    }

    @ParameterizedTest
    @NullAndEmptySource
    void areVCsCorrelatedShouldReturnFalseWhenMissingNameCredentialForBAVCRI(String missing)
            throws Exception {
        // Arrange
        var vcs =
                List.of(
                        TestFixtures.createVerifiableCredential(
                                USER_ID_1,
                                PASSPORT_CRI,
                                createCredentialWithNameAndBirthDate(
                                        "Jimbo", "Jones", "1000-01-01")),
                        TestFixtures.createVerifiableCredential(
                                USER_ID_1,
                                DCMAW_CRI,
                                createCredentialWithNameAndBirthDate(
                                        "Jimbo", "Jones", "1000-01-01")),
                        TestFixtures.createVerifiableCredential(
                                USER_ID_1,
                                BAV_CRI,
                                createCredentialWithNameAndBirthDate(missing, "Jones", missing)));
        mockCredentialIssuerConfig();

        // Act & Assert
        HttpResponseExceptionWithErrorBody thrownError =
                assertThrows(
                        HttpResponseExceptionWithErrorBody.class,
                        () -> userIdentityService.areVcsCorrelated(vcs));

        assertEquals(500, thrownError.getResponseCode());
        assertEquals(
                ErrorResponse.FAILED_NAME_CORRELATION.getCode(),
                thrownError.getErrorBody().get("error"));
        assertEquals(
                ErrorResponse.FAILED_NAME_CORRELATION.getMessage(),
                thrownError.getErrorBody().get("error_description"));
    }

    @Test
    void areVCsCorrelatedShouldReturnFalseIfExtraGivenNameInVc() throws Exception {
        // Arrange
        var vcs =
                List.of(
                        TestFixtures.createVerifiableCredential(
                                USER_ID_1,
                                ADDRESS_CRI,
                                createCredentialWithNameAndBirthDate(
                                        "Jimbo", "Jones", "1000-01-01")),
                        TestFixtures.createVerifiableCredential(
                                USER_ID_1,
                                PASSPORT_CRI,
                                createCredentialWithNameAndBirthDate(
                                        "Jimbo", "Jimmy", "Jones", "1000-01-01")),
                        TestFixtures.createVerifiableCredential(
                                USER_ID_1,
                                BAV_CRI,
                                createCredentialWithNameAndBirthDate(
                                        "Jimbo", "Jones", "1000-01-01")));
        mockCredentialIssuerConfig();

        // Act & Assert
        assertFalse(userIdentityService.areVcsCorrelated(vcs));
    }

    @Test
    void areVCsCorrelatedReturnsFalseWhenBirthDatesDiffer() throws Exception {
        // Arrange
        var vcs =
                List.of(
                        TestFixtures.createVerifiableCredential(
                                USER_ID_1,
                                PASSPORT_CRI,
                                createCredentialWithNameAndBirthDate(
                                        "Jimbo", "Jones", "1000-01-01")),
                        TestFixtures.createVerifiableCredential(
                                USER_ID_1,
                                DCMAW_CRI,
                                createCredentialWithNameAndBirthDate(
                                        "Jimbo", "Jones", "1000-01-01")),
                        TestFixtures.createVerifiableCredential(
                                USER_ID_1,
                                EXPERIAN_FRAUD_CRI,
                                createCredentialWithNameAndBirthDate(
                                        "Jimbo", "Jones", "2000-01-01")));
        mockCredentialIssuerConfig();

        // Act & Assert
        assertFalse(userIdentityService.areVcsCorrelated(vcs));
    }

    @ParameterizedTest
    @NullAndEmptySource
    void areVCsCorrelatedShouldThrowExceptionWhenMissingBirthDateProperty(String missing)
            throws Exception {
        // Arrange
        var vcs =
                List.of(
                        TestFixtures.createVerifiableCredential(
                                USER_ID_1,
                                ADDRESS_CRI,
                                createCredentialWithNameAndBirthDate(
                                        "Jimbo", "Jones", "1000-01-01")),
                        TestFixtures.createVerifiableCredential(
                                USER_ID_1,
                                PASSPORT_CRI,
                                createCredentialWithNameAndBirthDate("Jimbo", "Jones", missing)),
                        TestFixtures.createVerifiableCredential(
                                USER_ID_1,
                                EXPERIAN_FRAUD_CRI,
                                createCredentialWithNameAndBirthDate(
                                        "Jimbo", "Jones", "1000-01-01")));
        mockCredentialIssuerConfig();

        // Act & Assert
        HttpResponseExceptionWithErrorBody thrownError =
                assertThrows(
                        HttpResponseExceptionWithErrorBody.class,
                        () -> userIdentityService.areVcsCorrelated(vcs));

        assertEquals(500, thrownError.getResponseCode());
        assertEquals(
                ErrorResponse.FAILED_BIRTHDATE_CORRELATION.getCode(),
                thrownError.getErrorBody().get("error"));
        assertEquals(
                ErrorResponse.FAILED_BIRTHDATE_CORRELATION.getMessage(),
                thrownError.getErrorBody().get("error_description"));
    }

    @ParameterizedTest
    @NullAndEmptySource
    void areVCsCorrelatedShouldReturnTrueWhenAddressHasMissingBirthDate(String missing)
            throws Exception {
        // Arrange
        var vcs =
                List.of(
                        TestFixtures.createVerifiableCredential(
                                USER_ID_1,
                                ADDRESS_CRI,
                                createCredentialWithNameAndBirthDate("Jimbo", "Jones", missing)),
                        TestFixtures.createVerifiableCredential(
                                USER_ID_1,
                                PASSPORT_CRI,
                                createCredentialWithNameAndBirthDate(
                                        "Jimbo", "Jones", "1000-01-01")),
                        TestFixtures.createVerifiableCredential(
                                USER_ID_1,
                                EXPERIAN_FRAUD_CRI,
                                createCredentialWithNameAndBirthDate(
                                        "Jimbo", "Jones", "1000-01-01")));
        mockCredentialIssuerConfig();

        // Act & Assert
        assertTrue(userIdentityService.areVcsCorrelated(vcs));
    }

    @ParameterizedTest
    @NullAndEmptySource
    void areVCsCorrelatedShouldReturnTrueWhenBavHasMissingBirthDate(String missing)
            throws Exception {
        // Arrange
        var vcs =
                List.of(
                        TestFixtures.createVerifiableCredential(
                                USER_ID_1,
                                BAV_CRI,
                                createCredentialWithNameAndBirthDate("Jimbo", "Jones", missing)),
                        TestFixtures.createVerifiableCredential(
                                USER_ID_1,
                                PASSPORT_CRI,
                                createCredentialWithNameAndBirthDate(
                                        "Jimbo", "Jones", "1000-01-01")),
                        TestFixtures.createVerifiableCredential(
                                USER_ID_1,
                                EXPERIAN_FRAUD_CRI,
                                createCredentialWithNameAndBirthDate(
                                        "Jimbo", "Jones", "1000-01-01")));
        mockCredentialIssuerConfig();

        // Act & Assert
        assertTrue(userIdentityService.areVcsCorrelated(vcs));
    }

    @Test
    void areVCsCorrelatedShouldReturnFalseIfBavHasDifferentBirthDate() throws Exception {
        // Arrange
        var vcs =
                List.of(
                        TestFixtures.createVerifiableCredential(
                                USER_ID_1,
                                ADDRESS_CRI,
                                createCredentialWithNameAndBirthDate(
                                        "Jimbo", "Jones", "1000-01-01")),
                        TestFixtures.createVerifiableCredential(
                                USER_ID_1,
                                PASSPORT_CRI,
                                createCredentialWithNameAndBirthDate(
                                        "Jimbo", "Jones", "1000-01-01")),
                        TestFixtures.createVerifiableCredential(
                                USER_ID_1,
                                BAV_CRI,
                                createCredentialWithNameAndBirthDate(
                                        "Jimbo", "Jones", "2000-01-01")));
        mockCredentialIssuerConfig();

        // Act & Assert
        assertFalse(userIdentityService.areVcsCorrelated(vcs));
    }

    @Test
    void areVCsCorrelatedShouldNotIncludeVCsForNameNotDeemedSuccessful() throws Exception {
        // Arrange
        var vcs =
                List.of(
                        TestFixtures.createVerifiableCredential(
                                USER_ID_1,
                                ADDRESS_CRI,
                                createCredentialWithNameAndBirthDate(
                                        "Jimbo", "Jones", "1000-01-01")),
                        TestFixtures.createVerifiableCredential(
                                USER_ID_1,
                                PASSPORT_CRI,
                                createCredentialWithNameAndBirthDate(
                                        "Corky", "Jones", "1000-01-01", false)),
                        TestFixtures.createVerifiableCredential(
                                USER_ID_1,
                                EXPERIAN_FRAUD_CRI,
                                createCredentialWithNameAndBirthDate(
                                        "Jimbo", "Jones", "1000-01-01")));
        mockCredentialIssuerConfig();

        // Act & Assert
        assertTrue(userIdentityService.areVcsCorrelated(vcs));
    }

    @Test
    void areVCsCorrelatedShouldNotIncludeVCsForDOBNotDeemedSuccessful() throws Exception {
        // Arrange
        var vcs =
                List.of(
                        TestFixtures.createVerifiableCredential(
                                USER_ID_1,
                                ADDRESS_CRI,
                                createCredentialWithNameAndBirthDate(
                                        "Jimbo", "Jones", "1000-01-01")),
                        TestFixtures.createVerifiableCredential(
                                USER_ID_1,
                                PASSPORT_CRI,
                                createCredentialWithNameAndBirthDate(
                                        "Jimbo", "Jones", "1000-01-01")),
                        TestFixtures.createVerifiableCredential(
                                USER_ID_1,
                                EXPERIAN_FRAUD_CRI,
                                createCredentialWithNameAndBirthDate(
                                        "Jimbo", "Jones", "2000-01-01", false)));
        mockCredentialIssuerConfig();

        // Act & Assert
        assertTrue(userIdentityService.areVcsCorrelated(vcs));
    }

    @Test
    void areVCsCorrelatedReturnsFalseWhenExtraBirthDateInVc() throws Exception {
        // Arrange
        var vcs =
                List.of(
                        TestFixtures.createVerifiableCredential(
                                USER_ID_1,
                                PASSPORT_CRI,
                                createCredentialWithNameAndBirthDate(
                                        "Jimbo", "Jones", "1000-01-01")),
                        TestFixtures.createVerifiableCredential(
                                USER_ID_1,
                                DCMAW_CRI,
                                createCredentialWithNameAndBirthDate(
                                        "Jimbo", "Jones", "1000-01-01")),
                        TestFixtures.createVerifiableCredential(
                                USER_ID_1,
                                EXPERIAN_FRAUD_CRI,
                                createCredentialWithNameAndBirthDate(
                                        "Jimbo", "Jones", List.of("1000-01-01", "2000-01-01"))));
        mockCredentialIssuerConfig();

        // Act & Assert
        assertFalse(userIdentityService.areVcsCorrelated(vcs));
    }

    @Test
    void shouldSetIdentityClaimWhenVotIsP2() throws Exception {
        // Arrange
        var vcs =
                List.of(
                        PASSPORT_NON_DCMAW_SUCCESSFUL_VC,
                        vcExperianFraudScoreOne(),
                        vcExperianFraudScoreTwo(),
                        VC_ADDRESS);

        mockParamStoreCalls(paramsToMockForP2);
        mockCredentialIssuerConfig();

        // Act
        var credentials =
                userIdentityService.generateUserIdentity(
                        vcs, "test-sub", Vot.P2, emptyContraIndicators);

        // Assert
        IdentityClaim identityClaim = credentials.getIdentityClaim();

        assertEquals("GivenName", identityClaim.getName().get(0).getNameParts().get(0).getType());
        assertEquals("KENNETH", identityClaim.getName().get(0).getNameParts().get(0).getValue());

        assertEquals("1965-07-08", identityClaim.getBirthDate().get(0).getValue());
    }

    @Test
    void shouldSetIdentityClaimWhenVotIsP2MissingName() throws Exception {
        // Arrange
        var vcs =
                List.of(
                        vcPassportMissingName(),
                        vcPassportMissingBirthDate(),
                        vcExperianFraudScoreOne(),
                        vcExperianFraudScoreTwo(),
                        VC_ADDRESS);

        mockParamStoreCalls(paramsToMockForP2);
        mockCredentialIssuerConfig();

        // Act
        var credentials =
                userIdentityService.generateUserIdentity(
                        vcs, "test-sub", Vot.P2, emptyContraIndicators);

        // Assert
        IdentityClaim identityClaim = credentials.getIdentityClaim();

        assertEquals("GivenName", identityClaim.getName().get(0).getNameParts().get(0).getType());
        assertEquals("KENNETH", identityClaim.getName().get(0).getNameParts().get(0).getValue());

        assertEquals("1965-07-08", identityClaim.getBirthDate().get(0).getValue());
    }

    @Test
    void shouldNotSetIdentityClaimWhenVotIsP0() throws Exception {
        // Arrange
        var vcs = List.of(PASSPORT_NON_DCMAW_SUCCESSFUL_VC, vcExperianFraudScoreOne());

        mockParamStoreCalls(paramsToMockForP0WithNoCi);

        // Act
        var credentials =
                userIdentityService.generateUserIdentity(
                        vcs, "test-sub", Vot.P0, emptyContraIndicators);

        // Assert
        assertNull(credentials.getIdentityClaim());
    }

    @Test
    void shouldGetCorrectVot() throws Exception {
        // Arrange
        var vc = vcHmrcMigration();

        // Act
        var vot = userIdentityService.getVot(vc);

        // Assert
        assertEquals(Vot.PCL250, vot);
    }

    @Test
    void shouldThrowForInvalidVot() throws Exception {
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
    void shouldThrowExceptionWhenMissingNameProperty() throws CredentialParseException {
        // Arrange
        var vcs =
                List.of(
                        vcPassportMissingName(),
                        vcExperianFraudScoreOne(),
                        vcExperianFraudScoreTwo());

        when(mockConfigService.getSsmParameter(CORE_VTM_CLAIM)).thenReturn("mock-vtm-claim");
        mockCredentialIssuerConfig();

        // Act & Assert
        HttpResponseExceptionWithErrorBody thrownError =
                assertThrows(
                        HttpResponseExceptionWithErrorBody.class,
                        () ->
                                userIdentityService.generateUserIdentity(
                                        vcs, "test-sub", Vot.P2, emptyContraIndicators));

        assertEquals(500, thrownError.getResponseCode());
        assertEquals(
                ErrorResponse.FAILED_TO_GENERATE_IDENTIY_CLAIM.getCode(),
                thrownError.getErrorBody().get("error"));
        assertEquals(
                ErrorResponse.FAILED_TO_GENERATE_IDENTIY_CLAIM.getMessage(),
                thrownError.getErrorBody().get("error_description"));
    }

    @Test
    void shouldThrowExceptionWhenMissingBirthDateProperty() throws CredentialParseException {
        // Arrange
        var vcs =
                List.of(
                        vcPassportMissingBirthDate(),
                        vcExperianFraudScoreOne(),
                        vcExperianFraudScoreTwo());

        when(mockConfigService.getSsmParameter(CORE_VTM_CLAIM)).thenReturn("mock-vtm-claim");
        mockCredentialIssuerConfig();

        // Act & Assert
        HttpResponseExceptionWithErrorBody thrownError =
                assertThrows(
                        HttpResponseExceptionWithErrorBody.class,
                        () ->
                                userIdentityService.generateUserIdentity(
                                        vcs, "test-sub", Vot.P2, emptyContraIndicators));

        assertEquals(500, thrownError.getResponseCode());
        assertEquals(
                ErrorResponse.FAILED_TO_GENERATE_IDENTIY_CLAIM.getCode(),
                thrownError.getErrorBody().get("error"));
        assertEquals(
                ErrorResponse.FAILED_TO_GENERATE_IDENTIY_CLAIM.getMessage(),
                thrownError.getErrorBody().get("error_description"));
    }

    @Test
    void shouldSetPassportClaimWhenVotIsP2() throws Exception {
        // Arrange
        mockParamStoreCalls(paramsToMockForP2);
        mockCredentialIssuerConfig();

        var vcs =
                List.of(
                        PASSPORT_NON_DCMAW_SUCCESSFUL_VC,
                        vcExperianFraudScoreOne(),
                        vcExperianFraudScoreTwo(),
                        VC_ADDRESS);

        // Act
        var credentials =
                userIdentityService.generateUserIdentity(
                        vcs, "test-sub", Vot.P2, emptyContraIndicators);

        // Assert
        JsonNode passportClaim = credentials.getPassportClaim();

        assertEquals("321654987", passportClaim.get(0).get("documentNumber").asText());
        assertEquals("2030-01-01", passportClaim.get(0).get("expiryDate").asText());
    }

    @Test
    void shouldNotSetPassportClaimWhenVotIsP0() throws Exception {
        // Arrange
        var vcs = List.of(PASSPORT_NON_DCMAW_SUCCESSFUL_VC, vcExperianFraudScoreOne());

        mockParamStoreCalls(paramsToMockForP0WithNoCi);

        // Act
        var credentials =
                userIdentityService.generateUserIdentity(
                        vcs, "test-sub", Vot.P0, emptyContraIndicators);

        // Assert
        assertNull(credentials.getPassportClaim());
    }

    @Test
    void shouldReturnEmptyWhenMissingPassportProperty() throws Exception {
        // Arrange
        var vcs =
                List.of(
                        vcPassportMissingPassport(),
                        vcExperianFraudScoreOne(),
                        vcExperianFraudScoreTwo(),
                        VC_ADDRESS);

        mockParamStoreCalls(paramsToMockForP2);
        mockCredentialIssuerConfig();

        // Act
        var credentials =
                userIdentityService.generateUserIdentity(
                        vcs, "test-sub", Vot.P2, emptyContraIndicators);

        // Assert
        assertTrue(credentials.getPassportClaim().isEmpty());
    }

    @Test
    void generateUserIdentityShouldSetNinoClaimWhenVotIsP2() throws Exception {
        // Arrange
        mockParamStoreCalls(paramsToMockForP2);
        mockCredentialIssuerConfig();

        var vcs =
                List.of(
                        vcDrivingPermit(),
                        vcExperianFraudScoreOne(),
                        vcExperianFraudScoreTwo(),
                        VC_ADDRESS,
                        vcNinoSuccessful());

        // Act
        var credentials =
                userIdentityService.generateUserIdentity(
                        vcs, "test-sub", Vot.P2, emptyContraIndicators);

        // Assert
        JsonNode ninoClaim = credentials.getNinoClaim();
        assertEquals("AA000003D", ninoClaim.get(0).get("personalNumber").asText());
    }

    @Test
    void generateUserIdentityShouldNotSetNinoClaimWhenVotIsP0() throws Exception {
        // Arrange
        var vcs = List.of(vcDrivingPermit(), vcExperianFraudScoreOne(), vcNinoSuccessful());

        mockParamStoreCalls(paramsToMockForP0WithNoCi);

        // Act
        var credentials =
                userIdentityService.generateUserIdentity(
                        vcs, "test-sub", Vot.P0, emptyContraIndicators);

        // Assert
        assertNull(credentials.getNinoClaim());
    }

    @Test
    void generateUserIdentityShouldReturnEmptyNinoClaimWhenMissingNinoProperty() throws Exception {
        // Arrange
        var vcs =
                List.of(
                        vcDrivingPermit(),
                        vcExperianFraudScoreOne(),
                        vcExperianFraudScoreTwo(),
                        VC_ADDRESS,
                        vcNinoMissingSocialSecurityRecord());

        mockParamStoreCalls(paramsToMockForP2);
        mockCredentialIssuerConfig();

        // Act
        var credentials =
                userIdentityService.generateUserIdentity(
                        vcs, "test-sub", Vot.P2, emptyContraIndicators);

        // Assert
        assertNull(credentials.getNinoClaim());
    }

    @Test
    void generateUserIdentityShouldReturnEmptyNinoClaimWhenMissingNinoVc() throws Exception {
        // Arrange
        var vcs =
                List.of(
                        vcDrivingPermit(),
                        vcExperianFraudScoreOne(),
                        vcExperianFraudScoreTwo(),
                        VC_ADDRESS);

        mockParamStoreCalls(paramsToMockForP2);
        mockCredentialIssuerConfig();

        // Act
        var credentials =
                userIdentityService.generateUserIdentity(
                        vcs, "test-sub", Vot.P2, emptyContraIndicators);

        // Assert
        assertNull(credentials.getNinoClaim());
    }

    @Test
    void generateUserIdentityShouldReturnEmptyNinoClaimWhenNinoVcIsUnsuccessful() throws Exception {
        // Arrange
        var vcs =
                List.of(
                        vcDrivingPermit(),
                        vcExperianFraudScoreOne(),
                        vcExperianFraudScoreTwo(),
                        VC_ADDRESS,
                        vcNinoUnsuccessful());

        mockParamStoreCalls(paramsToMockForP2);
        mockCredentialIssuerConfig();

        // Act
        var credentials =
                userIdentityService.generateUserIdentity(
                        vcs, "test-sub", Vot.P2, emptyContraIndicators);

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
                        List.of(), "test-sub", Vot.P2, emptyContraIndicators);

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
                        List.of(), "test-sub", Vot.P2, emptyContraIndicators);

        // Assert
        assertEquals("mock-vtm-claim", credentials.getVtm());
    }

    @Test
    void generateUserIdentityShouldSetAddressClaimOnUserIdentity() throws Exception {
        // Arrange
        var vcs =
                List.of(
                        PASSPORT_NON_DCMAW_SUCCESSFUL_VC,
                        vcExperianFraudScoreOne(),
                        vcExperianFraudScoreTwo(),
                        vcAddressTwo());

        mockParamStoreCalls(paramsToMockForP2);
        mockCredentialIssuerConfig();

        // Act
        var userIdentity =
                userIdentityService.generateUserIdentity(
                        vcs, "test-sub", Vot.P2, emptyContraIndicators);

        // Assert
        JsonNode userIdentityJsonNode =
                objectMapper.readTree(objectMapper.writeValueAsString(userIdentity));
        JsonNode address = userIdentityJsonNode.get(ADDRESS_CLAIM_NAME).get(0);

        assertEquals("221B", address.get("buildingName").asText());
        assertEquals("MILTON ROAD", address.get("streetName").asText());
        assertEquals("Milton Keynes", address.get("addressLocality").asText());
        assertEquals("MK15 5BX", address.get("postalCode").asText());
        assertEquals("2024-01-01", address.get("validFrom").asText());
    }

    @Test
    void generateUserIdentityShouldThrowIfAddressVcMissingAddressProperty() {
        // Arrange
        var vcs =
                List.of(
                        PASSPORT_NON_DCMAW_SUCCESSFUL_VC,
                        vcExperianFraudScoreOne(),
                        vcExperianFraudScoreTwo(),
                        vcMissingCredentialSubject());

        when(mockConfigService.getSsmParameter(CORE_VTM_CLAIM)).thenReturn("mock-vtm-claim");
        mockCredentialIssuerConfig();

        // Act & Assert
        HttpResponseExceptionWithErrorBody thrownException =
                assertThrows(
                        HttpResponseExceptionWithErrorBody.class,
                        () ->
                                userIdentityService.generateUserIdentity(
                                        vcs, "test-sub", Vot.P2, emptyContraIndicators));

        assertEquals(500, thrownException.getResponseCode());
        assertEquals(
                ErrorResponse.FAILED_TO_GENERATE_ADDRESS_CLAIM.getCode(),
                thrownException.getErrorBody().get("error"));
        assertEquals(
                ErrorResponse.FAILED_TO_GENERATE_ADDRESS_CLAIM.getMessage(),
                thrownException.getErrorBody().get("error_description"));
    }

    @Test
    void shouldNotSetAddressClaimWhenVotIsP0() throws Exception {
        // Arrange
        var vcs = List.of(vcExperianFraudScoreOne(), vcExperianFraudScoreTwo(), vcAddressTwo());

        mockParamStoreCalls(paramsToMockForP0WithNoCi);

        // Act
        var credentials =
                userIdentityService.generateUserIdentity(
                        vcs, "test-sub", Vot.P0, emptyContraIndicators);

        // Assert
        assertNull(credentials.getAddressClaim());
    }

    @Test
    void shouldSetDrivingPermitClaimWhenVotIsP2() throws Exception {
        // Arrange
        var vcs = List.of(vcDrivingPermit(), vcExperianFraudScoreOne(), VC_ADDRESS);

        mockParamStoreCalls(paramsToMockForP2);
        mockCredentialIssuerConfig();

        // Act
        var credentials =
                userIdentityService.generateUserIdentity(
                        vcs, "test-sub", Vot.P2, emptyContraIndicators);

        // Assert
        JsonNode drivingPermitClaim = credentials.getDrivingPermitClaim();

        assertEquals("MORGA753116SM9IJ", drivingPermitClaim.get(0).get("personalNumber").asText());
        assertEquals("123456", drivingPermitClaim.get(0).get("issueNumber").asText());
        assertEquals("2042-10-01", drivingPermitClaim.get(0).get("expiryDate").asText());
    }

    @Test
    void shouldNotSetDrivingPermitClaimWhenVotIsP0() throws Exception {
        // Arrange
        var vcs = List.of(vcDrivingPermit(), vcExperianFraudScoreOne(), VC_ADDRESS);

        mockParamStoreCalls(paramsToMockForP0WithNoCi);

        // Act
        var credentials =
                userIdentityService.generateUserIdentity(
                        vcs, "test-sub", Vot.P0, emptyContraIndicators);

        // Assert
        JsonNode drivingPermitClaim = credentials.getDrivingPermitClaim();

        assertNull(drivingPermitClaim);
    }

    @Test
    void shouldNotSetDrivingPermitClaimWhenDrivingPermitVCIsMissing() throws Exception {
        // Arrange
        var vcs =
                List.of(
                        PASSPORT_NON_DCMAW_SUCCESSFUL_VC,
                        vcExperianFraudScoreOne(),
                        vcExperianFraudScoreTwo(),
                        VC_ADDRESS);

        mockParamStoreCalls(paramsToMockForP2);
        mockCredentialIssuerConfig();

        // Act
        var credentials =
                userIdentityService.generateUserIdentity(
                        vcs, "test-sub", Vot.P2, emptyContraIndicators);

        // Assert
        JsonNode drivingPermitClaim = credentials.getDrivingPermitClaim();

        assertNull(drivingPermitClaim);
    }

    @Test
    void shouldNotSetDrivingPermitClaimWhenDrivingPermitVCFailed() throws Exception {
        // Arrange
        var vcs =
                List.of(
                        vcDrivingPermitFailedChecks(),
                        PASSPORT_NON_DCMAW_SUCCESSFUL_VC,
                        vcExperianFraudScoreOne(),
                        VC_ADDRESS,
                        vcExperianFraudScoreTwo());

        mockParamStoreCalls(paramsToMockForP2);
        mockCredentialIssuerConfig();

        // Act
        var credentials =
                userIdentityService.generateUserIdentity(
                        vcs, "test-sub", Vot.P2, emptyContraIndicators);

        // Assert
        JsonNode drivingPermitClaim = credentials.getDrivingPermitClaim();

        assertNull(drivingPermitClaim);
    }

    @Test
    void shouldReturnEmptyWhenMissingDrivingPermitProperty() throws Exception {
        // Arrange
        var vcs = List.of(vcDrivingPermitMissingDrivingPermit());

        mockParamStoreCalls(paramsToMockForP2);
        mockCredentialIssuerConfig();

        // Act
        var credentials =
                userIdentityService.generateUserIdentity(
                        vcs, "test-sub", Vot.P2, emptyContraIndicators);

        // Assert
        assertTrue(credentials.getDrivingPermitClaim().isNull());
    }

    @Test
    void generateUserIdentityShouldSetExitCodeWhenP2AndAlwaysRequiredCiPresent() throws Exception {
        // Arrange
        mockParamStoreCalls(paramsToMockForP2);
        when(mockConfigService.getSsmParameter(RETURN_CODES_ALWAYS_REQUIRED)).thenReturn("🦆,🐧");
        when(mockConfigService.getContraIndicatorConfigMap())
                .thenReturn(
                        Map.of(
                                "X01", new ContraIndicatorConfig("X01", 4, -3, "🦆"),
                                "X02", new ContraIndicatorConfig("X02", 4, -3, "2"),
                                "Z03", new ContraIndicatorConfig("Z03", 4, -3, "3")));

        var contraIndicators =
                ContraIndicators.builder()
                        .usersContraIndicators(
                                List.of(
                                        ContraIndicator.builder().code("X01").build(),
                                        ContraIndicator.builder().code("X02").build(),
                                        ContraIndicator.builder().code("Z03").build()))
                        .build();

        // Act
        var userIdentity =
                userIdentityService.generateUserIdentity(
                        List.of(), "test-sub", Vot.P2, contraIndicators);

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
                        List.of(), "test-sub", Vot.P2, emptyContraIndicators);

        assertEquals(List.of(), userIdentity.getReturnCode());
    }

    @Test
    void generateUserIdentityShouldThrowWhenP2AndCiCodeNotFound() {
        // Arrange
        var emptyList = new ArrayList<VerifiableCredential>();
        when(mockConfigService.getSsmParameter(CORE_VTM_CLAIM)).thenReturn("mock-vtm-claim");
        when(mockConfigService.getContraIndicatorConfigMap())
                .thenReturn(Map.of("X01", new ContraIndicatorConfig("X01", 4, -3, "1")));

        ContraIndicators contraIndicators =
                ContraIndicators.builder()
                        .usersContraIndicators(
                                List.of(ContraIndicator.builder().code("wat").build()))
                        .build();

        // Act & Assert
        assertThrows(
                UnrecognisedCiException.class,
                () ->
                        userIdentityService.generateUserIdentity(
                                emptyList, "test-sub", Vot.P2, contraIndicators));
    }

    @Test
    void generateUserIdentityShouldSetExitCodeWhenBreachingCiThreshold() throws Exception {
        // Arrange
        mockParamStoreCalls(paramsToMockForP0);
        when(mockConfigService.getContraIndicatorConfigMap())
                .thenReturn(
                        Map.of(
                                "X01", new ContraIndicatorConfig("X01", 4, -3, "1"),
                                "X02", new ContraIndicatorConfig("X02", 4, -3, "2"),
                                "Z03", new ContraIndicatorConfig("Z03", 4, -3, "3")));

        ContraIndicators contraIndicators =
                ContraIndicators.builder()
                        .usersContraIndicators(
                                List.of(
                                        ContraIndicator.builder().code("X01").build(),
                                        ContraIndicator.builder()
                                                .code("X02")
                                                .mitigation(
                                                        List.of(
                                                                Mitigation.builder()
                                                                        .code("M01")
                                                                        .build()))
                                                .build(),
                                        ContraIndicator.builder().code("Z03").build()))
                        .build();

        // Act
        var userIdentity =
                userIdentityService.generateUserIdentity(
                        List.of(), "test-sub", Vot.P0, contraIndicators);

        // Assert
        assertEquals(
                List.of(new ReturnCode("1"), new ReturnCode("2"), new ReturnCode("3")),
                userIdentity.getReturnCode());
    }

    @Test
    void generateUserIdentityShouldThrowWhenBreachingAndCiCodeNotFound() {
        // Arrange
        var emptyList = new ArrayList<VerifiableCredential>();
        when(mockConfigService.getSsmParameter(CORE_VTM_CLAIM)).thenReturn("mock-vtm-claim");
        when(mockConfigService.getContraIndicatorConfigMap())
                .thenReturn(Map.of("X01", new ContraIndicatorConfig("X01", 4, -3, "1")));

        ContraIndicators contraIndicators =
                ContraIndicators.builder()
                        .usersContraIndicators(
                                List.of(ContraIndicator.builder().code("wat").build()))
                        .build();

        assertThrows(
                UnrecognisedCiException.class,
                () ->
                        userIdentityService.generateUserIdentity(
                                emptyList, "test-sub", Vot.P0, contraIndicators));
    }

    @Test
    void generateUserIdentityShouldDeduplicateExitCodes() throws Exception {
        // Arrange
        mockParamStoreCalls(paramsToMockForP0);
        when(mockConfigService.getContraIndicatorConfigMap())
                .thenReturn(
                        Map.of(
                                "X01", new ContraIndicatorConfig("X01", 4, -3, "1"),
                                "X02", new ContraIndicatorConfig("X02", 4, -3, "2"),
                                "Z03", new ContraIndicatorConfig("Z03", 4, -3, "3"),
                                "Z04", new ContraIndicatorConfig("Z04", 4, -3, "2")));

        ContraIndicators contraIndicators =
                ContraIndicators.builder()
                        .usersContraIndicators(
                                List.of(
                                        ContraIndicator.builder().code("X01").build(),
                                        ContraIndicator.builder().code("X02").build(),
                                        ContraIndicator.builder().code("Z03").build(),
                                        ContraIndicator.builder().code("Z04").build()))
                        .build();

        // Act
        var userIdentity =
                userIdentityService.generateUserIdentity(
                        List.of(), "test-sub", Vot.P0, contraIndicators);

        // Assert
        assertEquals(
                List.of(new ReturnCode("1"), new ReturnCode("2"), new ReturnCode("3")),
                userIdentity.getReturnCode());
    }

    @Test
    void generateUserIdentityShouldSetRequiredExitCodeWhenP0AndNotBreachingCiThreshold()
            throws Exception {
        // Arrange
        when(mockConfigService.getSsmParameter(CORE_VTM_CLAIM)).thenReturn("mock-vtm-claim");
        when(mockConfigService.getSsmParameter(CI_SCORING_THRESHOLD)).thenReturn("10");
        when(mockConfigService.getSsmParameter(RETURN_CODES_NON_CI_BREACHING_P0)).thenReturn("🐧");

        when(mockConfigService.getContraIndicatorConfigMap())
                .thenReturn(Map.of("X01", new ContraIndicatorConfig("X01", 4, -3, "1")));

        ContraIndicators contraIndicators =
                ContraIndicators.builder()
                        .usersContraIndicators(
                                List.of(ContraIndicator.builder().code("X01").build()))
                        .build();

        // Act
        var userIdentity =
                userIdentityService.generateUserIdentity(
                        List.of(), "test-sub", Vot.P0, contraIndicators);

        // Assert
        assertEquals(List.of(new ReturnCode("🐧")), userIdentity.getReturnCode());
        verify(mockConfigService, never()).getSsmParameter(RETURN_CODES_ALWAYS_REQUIRED);
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
    void isVcSuccessfulShouldThrowIfNoStatusFoundForIssuer() {
        // Arrange
        List<VcStatusDto> vcStatusDtos =
                List.of(
                        new VcStatusDto("issuer1", true),
                        new VcStatusDto("issuer2", true),
                        new VcStatusDto("issuer3", true));

        // Act & Assert
        assertThrows(
                NoVcStatusForIssuerException.class,
                () -> userIdentityService.isVcSuccessful(vcStatusDtos, "badIssuer"));
    }

    @Test
    void getCredentialsWithSingleCredentialAndOnlyOneValidEvidence()
            throws CredentialParseException {
        // Arrange
        var vcs = List.of(M1B_DCMAW_VC);
        claimedIdentityConfig.setRequiresAdditionalEvidence(true);
        when(mockConfigService.getOauthCriActiveConnectionConfig(any()))
                .thenReturn(claimedIdentityConfig);

        // Act & Assert
        assertTrue(userIdentityService.checkRequiresAdditionalEvidence(vcs));
    }

    @Test
    void
            getCredentialsWithSingleCredentialWithOnlyOneValidEvidenceAndRequiresAdditionalEvidencesFalse()
                    throws CredentialParseException {
        // Arrange
        var vcs = List.of(M1B_DCMAW_VC);
        claimedIdentityConfig.setRequiresAdditionalEvidence(false);
        when(mockConfigService.getOauthCriActiveConnectionConfig(any()))
                .thenReturn(claimedIdentityConfig);

        // Act & Assert
        assertFalse(userIdentityService.checkRequiresAdditionalEvidence(vcs));
    }

    @Test
    void getCredentialsWithMultipleCredentialsAndAllValidEvidence()
            throws CredentialParseException {
        // Arrange
        var vcs = List.of(M1B_DCMAW_VC, vcF2fM1a());

        // Act & Assert
        assertFalse(userIdentityService.checkRequiresAdditionalEvidence(vcs));
    }

    @Test
    void getCredentialsWithMultipleCredentialsAndAllInValidEvidence()
            throws CredentialParseException {
        // Arrange
        var vcs = List.of(vcExperianFraudScoreOne(), vcExperianFraudScoreTwo());

        // Act & Assert
        assertFalse(userIdentityService.checkRequiresAdditionalEvidence(vcs));
    }

    @Test
    void getCredentialsWithMultipleCredentialsAndValidAndInValidEvidence()
            throws CredentialParseException {
        // Arrange
        var vcs = List.of(M1B_DCMAW_VC, vcExperianFraudScoreTwo());

        claimedIdentityConfig.setRequiresAdditionalEvidence(true);
        when(mockConfigService.getOauthCriActiveConnectionConfig(any()))
                .thenReturn(claimedIdentityConfig);

        // Act & Assert
        assertTrue(userIdentityService.checkRequiresAdditionalEvidence(vcs));
    }

    @Test
    void shouldReturnCredentialsFromDataStoreForGPGProfile() throws Exception {
        var passportVc = PASSPORT_NON_DCMAW_SUCCESSFUL_VC;
        var fraudVc = vcExperianFraudScoreOne();
        var vcs = List.of(passportVc, fraudVc, vcHmrcMigration());

        mockParamStoreCalls(paramsToMockForP2);
        mockCredentialIssuerConfig();

        var credentials =
                userIdentityService.generateUserIdentity(
                        vcs, "test-sub", Vot.P2, emptyContraIndicators);

        assertEquals(2, credentials.getVcs().size());
        assertEquals(passportVc.getVcString(), credentials.getVcs().get(0));
        assertEquals(fraudVc.getVcString(), credentials.getVcs().get(1));
        assertEquals("test-sub", credentials.getSub());

        IdentityClaim identityClaim = credentials.getIdentityClaim();
        assertEquals("GivenName", identityClaim.getName().get(0).getNameParts().get(0).getType());
        assertEquals("KENNETH", identityClaim.getName().get(0).getNameParts().get(0).getValue());
        assertEquals("1965-07-08", identityClaim.getBirthDate().get(0).getValue());
    }

    @Test
    void shouldReturnCredentialsWithTicfFromDataStoreForOperationalProfile() throws Exception {
        var ticfVc = vcTicf();
        var hmrcMigrationVc = vcHmrcMigration();
        var vcs =
                List.of(
                        PASSPORT_NON_DCMAW_SUCCESSFUL_VC,
                        vcExperianFraudScoreOne(),
                        ticfVc,
                        hmrcMigrationVc);

        var credentials =
                userIdentityService.generateUserIdentity(
                        vcs, "test-sub", Vot.PCL200, emptyContraIndicators);

        assertEquals(2, credentials.getVcs().size());
        assertEquals(ticfVc.getVcString(), credentials.getVcs().get(0));
        assertEquals(hmrcMigrationVc.getVcString(), credentials.getVcs().get(1));
        assertEquals("test-sub", credentials.getSub());

        IdentityClaim identityClaim = credentials.getIdentityClaim();
        assertEquals("GivenName", identityClaim.getName().get(0).getNameParts().get(0).getType());
        assertEquals("KENNETH", identityClaim.getName().get(0).getNameParts().get(0).getValue());
        assertEquals("1965-07-08", identityClaim.getBirthDate().get(0).getValue());
    }

    @Test
    void shouldReturnCredentialsFromDataStoreForOperationalProfile() throws Exception {
        var hmrcVc = vcHmrcMigration();
        var vcs = List.of(PASSPORT_NON_DCMAW_SUCCESSFUL_VC, vcExperianFraudScoreOne(), hmrcVc);

        var credentials =
                userIdentityService.generateUserIdentity(
                        vcs, "test-sub", Vot.PCL200, emptyContraIndicators);

        assertEquals(1, credentials.getVcs().size());
        assertEquals(hmrcVc.getVcString(), credentials.getVcs().get(0));
        assertEquals("test-sub", credentials.getSub());

        IdentityClaim identityClaim = credentials.getIdentityClaim();
        assertEquals("GivenName", identityClaim.getName().get(0).getNameParts().get(0).getType());
        assertEquals("KENNETH", identityClaim.getName().get(0).getNameParts().get(0).getValue());
        assertEquals("1965-07-08", identityClaim.getBirthDate().get(0).getValue());
    }

    @Test
    void areVCsCorrelatedReturnsTrueWhenVcAreCorrelatedJustForGPG45Profile() throws Exception {
        // Arrange
        var vcs =
                List.of(
                        TestFixtures.createVerifiableCredential(
                                USER_ID_1,
                                ADDRESS_CRI,
                                createCredentialWithNameAndBirthDate(
                                        "Jimbo", "Jones", "1000-01-01")),
                        TestFixtures.createVerifiableCredential(
                                USER_ID_1,
                                PASSPORT_CRI,
                                createCredentialWithNameAndBirthDate(
                                        "Jimbo", "Jones", "1000-01-01")),
                        TestFixtures.createVerifiableCredential(
                                USER_ID_1,
                                BAV_CRI,
                                createCredentialWithNameAndBirthDate(
                                        "Jimbo", "Jones", "1000-01-01")),
                        vcTicf(),
                        vcHmrcMigration());
        mockCredentialIssuerConfig();

        // Act & Assert
        assertTrue(userIdentityService.areVcsCorrelated(vcs));
    }

    @Test
    void findIdentityReturnsIdentityClaimWhenEvidenceCheckIsFalse() throws Exception {
        var vcs = List.of(vcExperianFraudScoreOne());
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
    void findIdentityThrowsHttpResponseExceptionWithErrorBodyWhenNoNamePresent()
            throws CredentialParseException {
        var vcs = List.of(vcExperianFraudMissingName());
        assertThrows(
                HttpResponseExceptionWithErrorBody.class,
                () -> userIdentityService.findIdentityClaim(vcs, false));
    }

    @Test
    void findIdentityReturnsIdentityClaimForOperationalVC() throws Exception {
        var vcs = List.of(vcHmrcMigration());
        Optional<IdentityClaim> result = userIdentityService.findIdentityClaim(vcs);
        assertFalse(result.isEmpty());
    }

    @Test
    void findIdentityReturnsIdentityClaimForOperationalVcWithNoEvidence() throws Exception {
        var vcs = List.of(vcHmrcMigrationPCL250NoEvidence());
        Optional<IdentityClaim> result = userIdentityService.findIdentityClaim(vcs);
        assertFalse(result.isEmpty());
    }

    private void mockCredentialIssuerConfig() {
        NON_EVIDENCE_CRI_TYPES.forEach(
                credentialIssuer ->
                        when(mockConfigService.getComponentId(credentialIssuer))
                                .thenReturn(credentialIssuer));
    }

    private void mockParamStoreCalls(Map<ConfigurationVariable, String> params) {
        params.forEach(
                (key, value) -> when(mockConfigService.getSsmParameter(key)).thenReturn(value));
    }

    private String createCredentialWithNameAndBirthDate(
            String givenName, String familyName, String birthDate) throws Exception {
        var birthDateList = new ArrayList<String>();
        birthDateList.add(birthDate);
        return createCredentialWithNameAndBirthDate(
                givenName, null, familyName, birthDateList, true);
    }

    private String createCredentialWithNameAndBirthDate(
            String givenName, String middleName, String familyName, String birthDate)
            throws Exception {
        var birthDateList = new ArrayList<String>();
        birthDateList.add(birthDate);
        return createCredentialWithNameAndBirthDate(
                givenName, middleName, familyName, birthDateList, true);
    }

    private String createCredentialWithNameAndBirthDate(
            String givenName, String familyName, String birthDate, boolean isSuccessful)
            throws Exception {
        var birthDateList = new ArrayList<String>();
        birthDateList.add(birthDate);
        return createCredentialWithNameAndBirthDate(
                givenName, null, familyName, birthDateList, isSuccessful);
    }

    private String createCredentialWithNameAndBirthDate(
            String givenName, String familyName, List<String> birthDates) throws Exception {
        return createCredentialWithNameAndBirthDate(givenName, null, familyName, birthDates, true);
    }

    private String createCredentialWithNameAndBirthDate(
            String givenName,
            String middleName,
            String familyName,
            List<String> birthDates,
            boolean isSuccessful)
            throws Exception {
        var credentialSubject = new HashMap<String, Object>();
        var vcClaim = new HashMap<String, Object>();

        vcClaim.put(VC_CREDENTIAL_SUBJECT, credentialSubject);
        List<NameParts> nameParts =
                new ArrayList<>(
                        List.of(
                                new NameParts(givenName, VC_GIVEN_NAME),
                                new NameParts(familyName, VC_FAMILY_NAME)));
        if (middleName != null) {
            nameParts.add(1, new NameParts(middleName, VC_GIVEN_NAME));
        }

        credentialSubject.put(VC_NAME, List.of(new Name(nameParts)));

        credentialSubject.put(VC_BIRTH_DATE, birthDates.stream().map(BirthDate::new).toList());

        JWTClaimsSet claims =
                new JWTClaimsSet.Builder()
                        .claim(VC_CLAIM, vcClaim)
                        .issuer(
                                // address VC are always considered "successful" even without
                                // evidence
                                isSuccessful ? ADDRESS_CRI : PASSPORT_CRI)
                        .build();

        SignedJWT signedJWT = new SignedJWT(JWS_HEADER, claims);
        signedJWT.sign(jwtSigner);

        return signedJWT.serialize();
    }
}
