package uk.gov.di.ipv.core.library.service;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import uk.gov.di.ipv.core.library.domain.ContraIndicatorConfig;
import uk.gov.di.ipv.core.library.domain.ContraIndicators;
import uk.gov.di.ipv.core.library.domain.ErrorResponse;
import uk.gov.di.ipv.core.library.domain.IdentityClaim;
import uk.gov.di.ipv.core.library.domain.UserIdentity;
import uk.gov.di.ipv.core.library.domain.VectorOfTrust;
import uk.gov.di.ipv.core.library.domain.cimitvc.ContraIndicator;
import uk.gov.di.ipv.core.library.domain.cimitvc.Mitigation;
import uk.gov.di.ipv.core.library.dto.VcStatusDto;
import uk.gov.di.ipv.core.library.exceptions.CredentialParseException;
import uk.gov.di.ipv.core.library.exceptions.HttpResponseExceptionWithErrorBody;
import uk.gov.di.ipv.core.library.exceptions.NoVcStatusForIssuerException;
import uk.gov.di.ipv.core.library.exceptions.UnrecognisedCiException;
import uk.gov.di.ipv.core.library.persistence.DataStore;
import uk.gov.di.ipv.core.library.persistence.item.VcStoreItem;

import java.time.*;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;
import static uk.gov.di.ipv.core.library.config.ConfigurationVariable.ALWAYS_REQUIRED_EXIT_CODES;
import static uk.gov.di.ipv.core.library.config.ConfigurationVariable.CI_SCORING_THRESHOLD;
import static uk.gov.di.ipv.core.library.config.ConfigurationVariable.CORE_VTM_CLAIM;
import static uk.gov.di.ipv.core.library.config.CoreFeatureFlag.EXIT_CODES;
import static uk.gov.di.ipv.core.library.domain.CriConstants.NON_EVIDENCE_CRI_TYPES;
import static uk.gov.di.ipv.core.library.domain.UserIdentity.ADDRESS_CLAIM_NAME;
import static uk.gov.di.ipv.core.library.fixtures.TestFixtures.*;

@ExtendWith(MockitoExtension.class)
class UserIdentityServiceTest {
    private static final String USER_ID_1 = "user-id-1";
    private static final ObjectMapper objectMapper = new ObjectMapper();
    @Mock private ConfigService mockConfigService;
    @Mock private DataStore<VcStoreItem> mockDataStore;
    private final ContraIndicators emptyContraIndicators =
            ContraIndicators.builder().contraIndicatorsMap(new HashMap<>()).build();
    private UserIdentityService userIdentityService;

    @BeforeEach
    void setUp() {
        userIdentityService = new UserIdentityService(mockConfigService, mockDataStore);
    }

    @Test
    void shouldReturnCredentialsFromDataStore()
            throws HttpResponseExceptionWithErrorBody, CredentialParseException {
        List<VcStoreItem> vcStoreItems =
                List.of(
                        createVcStoreItem(
                                USER_ID_1,
                                "ukPassport",
                                VC_PASSPORT_NON_DCMAW_SUCCESSFUL,
                                Instant.now()),
                        createVcStoreItem(USER_ID_1, "fraud", VC_FRAUD_SCORE_1, Instant.now()));

        when(mockConfigService.getSsmParameter(CORE_VTM_CLAIM)).thenReturn("mock-vtm-claim");
        mockCredentialIssuerConfig();
        when(mockDataStore.getItems(anyString())).thenReturn(vcStoreItems);

        UserIdentity credentials =
                userIdentityService.generateUserIdentity(
                        USER_ID_1, "test-sub", "P2", emptyContraIndicators);

        assertEquals(VC_PASSPORT_NON_DCMAW_SUCCESSFUL, credentials.getVcs().get(0));
        assertEquals(VC_FRAUD_SCORE_1, credentials.getVcs().get(1));
        assertEquals("test-sub", credentials.getSub());
    }

    @Test
    void shouldReturnCredentialFromDataStoreForSpecificCri() {
        String ipvSessionId = "ipvSessionId";
        String criId = "criId";
        VcStoreItem credentialItem =
                createVcStoreItem(
                        USER_ID_1, "ukPassport", VC_PASSPORT_NON_DCMAW_SUCCESSFUL, Instant.now());

        when(mockDataStore.getItem(ipvSessionId, criId)).thenReturn(credentialItem);

        VcStoreItem retrievedCredentialItem =
                userIdentityService.getVcStoreItem(ipvSessionId, criId);

        assertEquals(credentialItem, retrievedCredentialItem);
    }

    @Test
    void shouldSetVotClaimToP2OnSuccessfulIdentityCheck() throws Exception {
        List<VcStoreItem> vcStoreItems =
                List.of(
                        createVcStoreItem(
                                USER_ID_1,
                                "ukPassport",
                                VC_PASSPORT_NON_DCMAW_SUCCESSFUL,
                                Instant.now()),
                        createVcStoreItem(USER_ID_1, "fraud", VC_FRAUD_SCORE_1, Instant.now()),
                        createVcStoreItem(USER_ID_1, "kbv", VC_KBV_SCORE_2, Instant.now()),
                        createVcStoreItem(USER_ID_1, "address", VC_ADDRESS, Instant.now()));

        when(mockConfigService.getSsmParameter(CORE_VTM_CLAIM)).thenReturn("mock-vtm-claim");
        mockCredentialIssuerConfig();
        when(mockDataStore.getItems(anyString())).thenReturn(vcStoreItems);

        UserIdentity credentials =
                userIdentityService.generateUserIdentity(
                        USER_ID_1, "test-sub", "P2", emptyContraIndicators);

        assertEquals(VectorOfTrust.P2.toString(), credentials.getVot());
    }

    @Test
    void checkBirthDateCorrelationInCredentialsReturnsTrueWhenBirthDatesSame() throws Exception {
        List<VcStoreItem> vcStoreItems =
                List.of(
                        createVcStoreItem(USER_ID_1, "ukPassport", VC_FRAUD_SCORE_1, Instant.now()),
                        createVcStoreItem(USER_ID_1, "dcmaw", VC_KBV_SCORE_2, Instant.now()));

        when(userIdentityService.getVcStoreItems(USER_ID_1)).thenReturn(vcStoreItems);
        mockCredentialIssuerConfig();

        boolean isValid = userIdentityService.checkBirthDateCorrelationInCredentials(USER_ID_1);

        assertTrue(isValid);
    }

    @Test
    void checkNameCorrelationInCredentialsReturnTrueWhenSameName() throws Exception {
        List<VcStoreItem> vcStoreItems =
                List.of(
                        createVcStoreItem(
                                USER_ID_1,
                                "ukPassport",
                                VC_PASSPORT_NON_DCMAW_FULL_NAME_SUCCESSFUL,
                                Instant.now()),
                        createVcStoreItem(
                                USER_ID_1,
                                "dcmaw",
                                VC_PASSPORT_NON_DCMAW_FULL_NAME_SUCCESSFUL,
                                Instant.now()),
                        createVcStoreItem(
                                USER_ID_1,
                                "bav",
                                VC_PASSPORT_NON_DCMAW_FULL_NAME_SUCCESSFUL,
                                Instant.now()));

        when(userIdentityService.getVcStoreItems(USER_ID_1)).thenReturn(vcStoreItems);
        mockCredentialIssuerConfig();

        boolean isValid =
                userIdentityService.checkNameAndFamilyNameCorrelationInCredentials(USER_ID_1);

        assertTrue(isValid);
    }

    @Test
    void checkBirthDateCorrelationInCredentialsReturnsFalseWhenBirthDatesDiffer() throws Exception {
        List<VcStoreItem> vcStoreItems =
                List.of(
                        createVcStoreItem(
                                USER_ID_1,
                                "ukPassport",
                                VC_PASSPORT_NON_DCMAW_SUCCESSFUL,
                                Instant.now()),
                        createVcStoreItem(USER_ID_1, "dcmaw", VC_KBV_SCORE_2, Instant.now()));

        when(userIdentityService.getVcStoreItems(USER_ID_1)).thenReturn(vcStoreItems);
        mockCredentialIssuerConfig();

        boolean isValid = userIdentityService.checkBirthDateCorrelationInCredentials(USER_ID_1);

        assertFalse(isValid);
    }

    @Test
    void checkNameCorrelationInCredentialsReturnFalseWhenNameDiffer() throws Exception {
        List<VcStoreItem> vcStoreItems =
                List.of(
                        createVcStoreItem(USER_ID_1, "ukPassport", VC_FRAUD_SCORE_1, Instant.now()),
                        createVcStoreItem(
                                USER_ID_1,
                                "dcmaw",
                                VC_PASSPORT_NON_DCMAW_FULL_NAME_SUCCESSFUL,
                                Instant.now()));

        when(userIdentityService.getVcStoreItems(USER_ID_1)).thenReturn(vcStoreItems);
        mockCredentialIssuerConfig();

        boolean isValid =
                userIdentityService.checkNameAndFamilyNameCorrelationInCredentials(USER_ID_1);

        assertFalse(isValid);
    }

    @Test
    void checkNameCorrelationInCredentialsReturnFalseWhenNameDifferForBavCRI() throws Exception {
        List<VcStoreItem> vcStoreItems =
                List.of(
                        createVcStoreItem(USER_ID_1, "ukPassport", VC_FRAUD_SCORE_1, Instant.now()),
                        createVcStoreItem(
                                USER_ID_1, "bav", VC_PASSPORT_NON_DCMAW_SUCCESSFUL, Instant.now()));

        when(userIdentityService.getVcStoreItems(USER_ID_1)).thenReturn(vcStoreItems);
        mockCredentialIssuerConfig();

        boolean isValid =
                userIdentityService.checkNameAndFamilyNameCorrelationInCredentials(USER_ID_1);

        assertFalse(isValid);
    }

    @Test
    void checkNameCorrelationWithSameNamesAndMissingNameCredentialsForReturnTrue()
            throws Exception {
        List<VcStoreItem> vcStoreItems =
                List.of(
                        createVcStoreItem(
                                USER_ID_1, "ukPassport", VC_PASSPORT_MISSING_NAME, Instant.now()),
                        createVcStoreItem(
                                USER_ID_1,
                                "ukPassport",
                                VC_PASSPORT_NON_DCMAW_SUCCESSFUL,
                                Instant.now()),
                        createVcStoreItem(
                                USER_ID_1, "address", VC_PASSPORT_MISSING_NAME, Instant.now()),
                        createVcStoreItem(
                                USER_ID_1,
                                "dcmaw",
                                VC_PASSPORT_NON_DCMAW_SUCCESSFUL,
                                Instant.now()));

        when(userIdentityService.getVcStoreItems(USER_ID_1)).thenReturn(vcStoreItems);
        mockCredentialIssuerConfig();

        boolean isValid =
                userIdentityService.checkNameAndFamilyNameCorrelationInCredentials(USER_ID_1);

        assertTrue(isValid);
    }

    @Test
    void checkNameCorrelationWithMissingNameCredentialsForReturnTrue() throws Exception {
        List<VcStoreItem> vcStoreItems =
                List.of(
                        createVcStoreItem(
                                USER_ID_1, "ukPassport", VC_PASSPORT_MISSING_NAME, Instant.now()),
                        createVcStoreItem(
                                USER_ID_1, "address", VC_PASSPORT_MISSING_NAME, Instant.now()));

        when(userIdentityService.getVcStoreItems(USER_ID_1)).thenReturn(vcStoreItems);
        mockCredentialIssuerConfig();

        boolean isValid =
                userIdentityService.checkNameAndFamilyNameCorrelationInCredentials(USER_ID_1);

        assertTrue(isValid);
    }

    @Test
    void checkNameCorrelationWithMissingNameCredentialsForOnlyBAVCRIReturnFalse() throws Exception {
        List<VcStoreItem> vcStoreItems =
                List.of(
                        createVcStoreItem(
                                USER_ID_1,
                                "ukPassport",
                                VC_PASSPORT_NON_DCMAW_SUCCESSFUL,
                                Instant.now()),
                        createVcStoreItem(USER_ID_1, "dcmaw", VC_KBV_SCORE_2, Instant.now()),
                        createVcStoreItem(
                                USER_ID_1, "bav", VC_PASSPORT_MISSING_BIRTH_DATE, Instant.now()));

        when(userIdentityService.getVcStoreItems(USER_ID_1)).thenReturn(vcStoreItems);
        mockCredentialIssuerConfig();

        boolean isValid =
                userIdentityService.checkNameAndFamilyNameCorrelationInCredentials(USER_ID_1);

        assertFalse(isValid);
    }

    @Test
    void checkBirthDateCorrelationWithSameBirthDatesAndMissingBirthDateCredentialsForReturnTrue()
            throws Exception {
        List<VcStoreItem> vcStoreItems =
                List.of(
                        createVcStoreItem(
                                USER_ID_1,
                                "ukPassport",
                                VC_PASSPORT_MISSING_BIRTH_DATE,
                                Instant.now()),
                        createVcStoreItem(USER_ID_1, "ukPassport", VC_FRAUD_SCORE_1, Instant.now()),
                        createVcStoreItem(
                                USER_ID_1,
                                "ukPassport",
                                VC_PASSPORT_MISSING_BIRTH_DATE,
                                Instant.now()),
                        createVcStoreItem(USER_ID_1, "dcmaw", VC_KBV_SCORE_2, Instant.now()));

        when(userIdentityService.getVcStoreItems(USER_ID_1)).thenReturn(vcStoreItems);
        mockCredentialIssuerConfig();

        boolean isValid = userIdentityService.checkBirthDateCorrelationInCredentials(USER_ID_1);

        assertTrue(isValid);
    }

    @Test
    void checkBirthDateCorrelationWithMissingBirthDateCredentialsForReturnTrue() throws Exception {
        List<VcStoreItem> vcStoreItems =
                List.of(
                        createVcStoreItem(
                                USER_ID_1,
                                "ukPassport",
                                VC_PASSPORT_MISSING_BIRTH_DATE,
                                Instant.now()),
                        createVcStoreItem(
                                USER_ID_1,
                                "ukPassport",
                                VC_PASSPORT_MISSING_BIRTH_DATE,
                                Instant.now()));

        when(userIdentityService.getVcStoreItems(USER_ID_1)).thenReturn(vcStoreItems);
        mockCredentialIssuerConfig();

        boolean isValid = userIdentityService.checkBirthDateCorrelationInCredentials(USER_ID_1);

        assertTrue(isValid);
    }

    @Test
    void checkBirthDateCorrelationWithMissingBirthDateForAllCRIsAndReturnTrue() throws Exception {
        List<VcStoreItem> vcStoreItems =
                List.of(
                        createVcStoreItem(
                                USER_ID_1, "bav", VC_PASSPORT_MISSING_BIRTH_DATE, Instant.now()),
                        createVcStoreItem(
                                USER_ID_1,
                                "ukPassport",
                                VC_PASSPORT_MISSING_BIRTH_DATE,
                                Instant.now()),
                        createVcStoreItem(
                                USER_ID_1,
                                "address",
                                VC_PASSPORT_MISSING_BIRTH_DATE,
                                Instant.now()));

        when(userIdentityService.getVcStoreItems(USER_ID_1)).thenReturn(vcStoreItems);
        mockCredentialIssuerConfig();

        boolean isValid = userIdentityService.checkBirthDateCorrelationInCredentials(USER_ID_1);

        assertTrue(isValid);
    }

    @Test
    void checkBirthDateCorrelationWithMissingBirthDateForOnlyBAVCRIAndReturnTrue()
            throws Exception {
        List<VcStoreItem> vcStoreItems =
                List.of(
                        createVcStoreItem(USER_ID_1, "ukPassport", VC_FRAUD_SCORE_1, Instant.now()),
                        createVcStoreItem(USER_ID_1, "dcmaw", VC_KBV_SCORE_2, Instant.now()),
                        createVcStoreItem(
                                USER_ID_1, "bav", VC_PASSPORT_MISSING_BIRTH_DATE, Instant.now()));

        when(userIdentityService.getVcStoreItems(USER_ID_1)).thenReturn(vcStoreItems);
        mockCredentialIssuerConfig();

        boolean isValid = userIdentityService.checkBirthDateCorrelationInCredentials(USER_ID_1);

        assertTrue(isValid);
    }

    @Test
    void checkBirthDateCorrelationWithBirthDateIsNotEmptyForBAVCRIAndReturnTrue() throws Exception {
        List<VcStoreItem> vcStoreItems =
                List.of(
                        createVcStoreItem(USER_ID_1, "ukPassport", VC_FRAUD_SCORE_1, Instant.now()),
                        createVcStoreItem(USER_ID_1, "dcmaw", VC_KBV_SCORE_2, Instant.now()),
                        createVcStoreItem(USER_ID_1, "bav", VC_FRAUD_SCORE_1, Instant.now()));

        when(userIdentityService.getVcStoreItems(USER_ID_1)).thenReturn(vcStoreItems);
        mockCredentialIssuerConfig();

        boolean isValid = userIdentityService.checkBirthDateCorrelationInCredentials(USER_ID_1);

        assertTrue(isValid);
    }

    @Test
    void checkBirthDateCorrelationWithBirthDateIsNotEmptyButDifferentDOBForBAVCRIAndReturnFalse()
            throws Exception {
        List<VcStoreItem> vcStoreItems =
                List.of(
                        createVcStoreItem(USER_ID_1, "ukPassport", VC_FRAUD_SCORE_1, Instant.now()),
                        createVcStoreItem(USER_ID_1, "dcmaw", VC_KBV_SCORE_2, Instant.now()),
                        createVcStoreItem(
                                USER_ID_1, "bav", VC_PASSPORT_NON_DCMAW_SUCCESSFUL, Instant.now()));

        when(userIdentityService.getVcStoreItems(USER_ID_1)).thenReturn(vcStoreItems);
        mockCredentialIssuerConfig();

        boolean isValid = userIdentityService.checkBirthDateCorrelationInCredentials(USER_ID_1);

        assertFalse(isValid);
    }

    @Test
    void shouldSetIdentityClaimWhenVotIsP2() throws Exception {
        List<VcStoreItem> vcStoreItems =
                List.of(
                        createVcStoreItem(
                                USER_ID_1,
                                "ukPassport",
                                VC_PASSPORT_NON_DCMAW_SUCCESSFUL,
                                Instant.now()),
                        createVcStoreItem(USER_ID_1, "fraud", VC_FRAUD_SCORE_1, Instant.now()),
                        createVcStoreItem(USER_ID_1, "kbv", VC_KBV_SCORE_2, Instant.now()),
                        createVcStoreItem(USER_ID_1, "address", VC_ADDRESS, Instant.now()));

        when(mockConfigService.getSsmParameter(CORE_VTM_CLAIM)).thenReturn("mock-vtm-claim");
        mockCredentialIssuerConfig();
        when(mockDataStore.getItems(anyString())).thenReturn(vcStoreItems);

        UserIdentity credentials =
                userIdentityService.generateUserIdentity(
                        USER_ID_1, "test-sub", "P2", emptyContraIndicators);

        IdentityClaim identityClaim = credentials.getIdentityClaim();

        assertEquals("GivenName", identityClaim.getName().get(0).getNameParts().get(0).getType());
        assertEquals("Paul", identityClaim.getName().get(0).getNameParts().get(0).getValue());

        assertEquals("2020-02-03", identityClaim.getBirthDate().get(0).getValue());
    }

    @Test
    void shouldSetIdentityClaimWhenVotIsP2MissingName() throws Exception {
        List<VcStoreItem> vcStoreItems =
                List.of(
                        createVcStoreItem(
                                USER_ID_1, "ukPassport", VC_PASSPORT_MISSING_NAME, Instant.now()),
                        createVcStoreItem(
                                USER_ID_1, "dcmaw", VC_PASSPORT_MISSING_BIRTH_DATE, Instant.now()),
                        createVcStoreItem(USER_ID_1, "fraud", VC_FRAUD_SCORE_1, Instant.now()),
                        createVcStoreItem(USER_ID_1, "kbv", VC_KBV_SCORE_2, Instant.now()),
                        createVcStoreItem(USER_ID_1, "address", VC_ADDRESS, Instant.now()));

        when(mockConfigService.getSsmParameter(CORE_VTM_CLAIM)).thenReturn("mock-vtm-claim");
        mockCredentialIssuerConfig();
        when(mockDataStore.getItems(anyString())).thenReturn(vcStoreItems);

        UserIdentity credentials =
                userIdentityService.generateUserIdentity(
                        USER_ID_1, "test-sub", "P2", emptyContraIndicators);

        IdentityClaim identityClaim = credentials.getIdentityClaim();

        assertEquals("GivenName", identityClaim.getName().get(0).getNameParts().get(0).getType());
        assertEquals("Paul", identityClaim.getName().get(0).getNameParts().get(0).getValue());

        assertEquals("2020-02-03", identityClaim.getBirthDate().get(0).getValue());
    }

    @Test
    void shouldNotSetIdentityClaimWhenVotIsP0() throws Exception {
        List<VcStoreItem> vcStoreItems =
                List.of(
                        createVcStoreItem(
                                USER_ID_1,
                                "ukPassport",
                                VC_PASSPORT_NON_DCMAW_SUCCESSFUL,
                                Instant.now()),
                        createVcStoreItem(USER_ID_1, "fraud", VC_FRAUD_SCORE_1, Instant.now()));

        when(mockDataStore.getItems(anyString())).thenReturn(vcStoreItems);

        UserIdentity credentials =
                userIdentityService.generateUserIdentity(
                        USER_ID_1, "test-sub", "P0", emptyContraIndicators);

        assertNull(credentials.getIdentityClaim());
    }

    @Test
    void shouldThrowExceptionWhenMissingNameProperty() {
        List<VcStoreItem> vcStoreItems =
                List.of(
                        createVcStoreItem(
                                USER_ID_1, "ukPassport", VC_PASSPORT_MISSING_NAME, Instant.now()),
                        createVcStoreItem(USER_ID_1, "fraud", VC_FRAUD_SCORE_1, Instant.now()),
                        createVcStoreItem(USER_ID_1, "kbv", VC_KBV_SCORE_2, Instant.now()));

        when(mockConfigService.getSsmParameter(CORE_VTM_CLAIM)).thenReturn("mock-vtm-claim");
        mockCredentialIssuerConfig();
        when(mockDataStore.getItems(anyString())).thenReturn(vcStoreItems);

        HttpResponseExceptionWithErrorBody thrownError =
                assertThrows(
                        HttpResponseExceptionWithErrorBody.class,
                        () ->
                                userIdentityService.generateUserIdentity(
                                        USER_ID_1, "test-sub", "P2", emptyContraIndicators));

        assertEquals(500, thrownError.getResponseCode());
        assertEquals(
                ErrorResponse.FAILED_TO_GENERATE_IDENTIY_CLAIM.getCode(),
                thrownError.getErrorBody().get("error"));
        assertEquals(
                ErrorResponse.FAILED_TO_GENERATE_IDENTIY_CLAIM.getMessage(),
                thrownError.getErrorBody().get("error_description"));
    }

    @Test
    void shouldThrowExceptionWhenMissingBirthDateProperty() {
        List<VcStoreItem> vcStoreItems =
                List.of(
                        createVcStoreItem(
                                USER_ID_1,
                                "ukPassport",
                                VC_PASSPORT_MISSING_BIRTH_DATE,
                                Instant.now()),
                        createVcStoreItem(USER_ID_1, "fraud", VC_FRAUD_SCORE_1, Instant.now()),
                        createVcStoreItem(USER_ID_1, "kbv", VC_KBV_SCORE_2, Instant.now()));

        when(mockConfigService.getSsmParameter(CORE_VTM_CLAIM)).thenReturn("mock-vtm-claim");
        mockCredentialIssuerConfig();
        when(mockDataStore.getItems(anyString())).thenReturn(vcStoreItems);

        HttpResponseExceptionWithErrorBody thrownError =
                assertThrows(
                        HttpResponseExceptionWithErrorBody.class,
                        () ->
                                userIdentityService.generateUserIdentity(
                                        USER_ID_1, "test-sub", "P2", emptyContraIndicators));

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
        when(mockConfigService.getSsmParameter(CORE_VTM_CLAIM)).thenReturn("mock-vtm-claim");
        mockCredentialIssuerConfig();

        List<VcStoreItem> vcStoreItems =
                List.of(
                        createVcStoreItem(
                                USER_ID_1,
                                "ukPassport",
                                VC_PASSPORT_NON_DCMAW_SUCCESSFUL,
                                Instant.now()),
                        createVcStoreItem(USER_ID_1, "fraud", VC_FRAUD_SCORE_1, Instant.now()),
                        createVcStoreItem(USER_ID_1, "kbv", VC_KBV_SCORE_2, Instant.now()),
                        createVcStoreItem(USER_ID_1, "address", VC_ADDRESS, Instant.now()));

        when(mockDataStore.getItems(anyString())).thenReturn(vcStoreItems);

        UserIdentity credentials =
                userIdentityService.generateUserIdentity(
                        USER_ID_1, "test-sub", "P2", emptyContraIndicators);

        JsonNode passportClaim = credentials.getPassportClaim();

        assertEquals("123456789", passportClaim.get(0).get("documentNumber").asText());
        assertEquals("2020-01-01", passportClaim.get(0).get("expiryDate").asText());
    }

    @Test
    void shouldNotSetPassportClaimWhenVotIsP0() throws Exception {
        List<VcStoreItem> vcStoreItems =
                List.of(
                        createVcStoreItem(
                                USER_ID_1,
                                "ukPassport",
                                VC_PASSPORT_NON_DCMAW_SUCCESSFUL,
                                Instant.now()),
                        createVcStoreItem(USER_ID_1, "fraud", VC_FRAUD_SCORE_1, Instant.now()));

        when(mockDataStore.getItems(anyString())).thenReturn(vcStoreItems);

        UserIdentity credentials =
                userIdentityService.generateUserIdentity(
                        USER_ID_1, "test-sub", "P0", emptyContraIndicators);

        assertNull(credentials.getPassportClaim());
    }

    @Test
    void shouldReturnEmptyWhenMissingPassportProperty() throws Exception {
        List<VcStoreItem> vcStoreItems =
                List.of(
                        createVcStoreItem(
                                USER_ID_1,
                                "ukPassport",
                                VC_PASSPORT_MISSING_PASSPORT,
                                Instant.now()),
                        createVcStoreItem(USER_ID_1, "fraud", VC_FRAUD_SCORE_1, Instant.now()),
                        createVcStoreItem(USER_ID_1, "kbv", VC_KBV_SCORE_2, Instant.now()),
                        createVcStoreItem(USER_ID_1, "address", VC_ADDRESS, Instant.now()));

        when(mockConfigService.getSsmParameter(CORE_VTM_CLAIM)).thenReturn("mock-vtm-claim");
        mockCredentialIssuerConfig();
        when(mockDataStore.getItems(anyString())).thenReturn(vcStoreItems);

        UserIdentity credentials =
                userIdentityService.generateUserIdentity(
                        USER_ID_1, "test-sub", "P2", emptyContraIndicators);

        assertNull(credentials.getPassportClaim());
    }

    @Test
    void generateUserIdentityShouldSetNinoClaimWhenVotIsP2() throws Exception {
        // Arrange
        when(mockConfigService.getSsmParameter(CORE_VTM_CLAIM)).thenReturn("mock-vtm-claim");
        mockCredentialIssuerConfig();

        List<VcStoreItem> vcStoreItems =
                List.of(
                        createVcStoreItem(
                                USER_ID_1, "dcmaw", VC_DRIVING_PERMIT_DCMAW, Instant.now()),
                        createVcStoreItem(USER_ID_1, "fraud", VC_FRAUD_SCORE_1, Instant.now()),
                        createVcStoreItem(USER_ID_1, "kbv", VC_KBV_SCORE_2, Instant.now()),
                        createVcStoreItem(USER_ID_1, "address", VC_ADDRESS, Instant.now()),
                        createVcStoreItem(USER_ID_1, "nino", VC_NINO_SUCCESSFUL, Instant.now()));

        when(mockDataStore.getItems(anyString())).thenReturn(vcStoreItems);

        // Act
        UserIdentity credentials =
                userIdentityService.generateUserIdentity(
                        USER_ID_1, "test-sub", "P2", emptyContraIndicators);

        // Assert
        JsonNode ninoClaim = credentials.getNinoClaim();
        assertEquals("AA000003D", ninoClaim.get(0).get("personalNumber").asText());
    }

    @Test
    void generateUserIdentityShouldNotSetNinoClaimWhenVotIsP0()
            throws HttpResponseExceptionWithErrorBody, CredentialParseException {
        // Arrange
        List<VcStoreItem> vcStoreItems =
                List.of(
                        createVcStoreItem(
                                USER_ID_1, "dcmaw", VC_DRIVING_PERMIT_DCMAW, Instant.now()),
                        createVcStoreItem(USER_ID_1, "fraud", VC_FRAUD_SCORE_1, Instant.now()),
                        createVcStoreItem(USER_ID_1, "nino", VC_NINO_SUCCESSFUL, Instant.now()));

        when(mockDataStore.getItems(anyString())).thenReturn(vcStoreItems);

        // Act
        UserIdentity credentials =
                userIdentityService.generateUserIdentity(
                        USER_ID_1, "test-sub", "P0", emptyContraIndicators);

        // Assert
        assertNull(credentials.getNinoClaim());
    }

    @Test
    void generateUserIdentityShouldReturnEmptyNinoClaimWhenMissingNinoProperty()
            throws HttpResponseExceptionWithErrorBody, CredentialParseException {
        // Arrange
        when(mockConfigService.getSsmParameter(CORE_VTM_CLAIM)).thenReturn("mock-vtm-claim");
        mockCredentialIssuerConfig();

        List<VcStoreItem> vcStoreItems =
                List.of(
                        createVcStoreItem(
                                USER_ID_1, "dcmaw", VC_DRIVING_PERMIT_DCMAW, Instant.now()),
                        createVcStoreItem(USER_ID_1, "fraud", VC_FRAUD_SCORE_1, Instant.now()),
                        createVcStoreItem(USER_ID_1, "kbv", VC_KBV_SCORE_2, Instant.now()),
                        createVcStoreItem(USER_ID_1, "address", VC_ADDRESS, Instant.now()),
                        createVcStoreItem(
                                USER_ID_1,
                                "nino",
                                VC_NINO_MISSING_SOCIAL_SECURITY_RECORD,
                                Instant.now()));

        when(mockConfigService.getSsmParameter(CORE_VTM_CLAIM)).thenReturn("mock-vtm-claim");
        mockCredentialIssuerConfig();
        when(mockDataStore.getItems(anyString())).thenReturn(vcStoreItems);

        // Act
        UserIdentity credentials =
                userIdentityService.generateUserIdentity(
                        USER_ID_1, "test-sub", "P2", emptyContraIndicators);

        // Assert
        assertNull(credentials.getNinoClaim());
    }

    @Test
    void generateUserIdentityShouldReturnEmptyNinoClaimWhenMissingNinoVc()
            throws HttpResponseExceptionWithErrorBody, CredentialParseException {
        // Arrange
        when(mockConfigService.getSsmParameter(CORE_VTM_CLAIM)).thenReturn("mock-vtm-claim");
        mockCredentialIssuerConfig();

        List<VcStoreItem> vcStoreItems =
                List.of(
                        createVcStoreItem(
                                USER_ID_1, "dcmaw", VC_DRIVING_PERMIT_DCMAW, Instant.now()),
                        createVcStoreItem(USER_ID_1, "fraud", VC_FRAUD_SCORE_1, Instant.now()),
                        createVcStoreItem(USER_ID_1, "kbv", VC_KBV_SCORE_2, Instant.now()),
                        createVcStoreItem(USER_ID_1, "address", VC_ADDRESS, Instant.now()));

        when(mockConfigService.getSsmParameter(CORE_VTM_CLAIM)).thenReturn("mock-vtm-claim");
        mockCredentialIssuerConfig();
        when(mockDataStore.getItems(anyString())).thenReturn(vcStoreItems);

        // Act
        UserIdentity credentials =
                userIdentityService.generateUserIdentity(
                        USER_ID_1, "test-sub", "P2", emptyContraIndicators);

        // Assert
        assertNull(credentials.getNinoClaim());
    }

    @Test
    void generateUserIdentityShouldReturnEmptyNinoClaimWhenNinoVcIsUnsuccessful()
            throws HttpResponseExceptionWithErrorBody, CredentialParseException {
        // Arrange
        when(mockConfigService.getSsmParameter(CORE_VTM_CLAIM)).thenReturn("mock-vtm-claim");
        mockCredentialIssuerConfig();

        List<VcStoreItem> vcStoreItems =
                List.of(
                        createVcStoreItem(
                                USER_ID_1, "dcmaw", VC_DRIVING_PERMIT_DCMAW, Instant.now()),
                        createVcStoreItem(USER_ID_1, "fraud", VC_FRAUD_SCORE_1, Instant.now()),
                        createVcStoreItem(USER_ID_1, "kbv", VC_KBV_SCORE_2, Instant.now()),
                        createVcStoreItem(USER_ID_1, "address", VC_ADDRESS, Instant.now()),
                        createVcStoreItem(USER_ID_1, "nino", VC_NINO_UNSUCCESSFUL, Instant.now()));

        when(mockConfigService.getSsmParameter(CORE_VTM_CLAIM)).thenReturn("mock-vtm-claim");
        mockCredentialIssuerConfig();
        when(mockDataStore.getItems(anyString())).thenReturn(vcStoreItems);

        // Act
        UserIdentity credentials =
                userIdentityService.generateUserIdentity(
                        USER_ID_1, "test-sub", "P2", emptyContraIndicators);

        // Assert
        assertNull(credentials.getNinoClaim());
    }

    @Test
    void shouldSetSubClaimOnUserIdentity() throws Exception {
        when(mockConfigService.getSsmParameter(CORE_VTM_CLAIM)).thenReturn("mock-vtm-claim");

        UserIdentity credentials =
                userIdentityService.generateUserIdentity(
                        USER_ID_1, "test-sub", "P2", emptyContraIndicators);

        assertEquals("test-sub", credentials.getSub());
    }

    @Test
    void shouldSetVtmClaimOnUserIdentity() throws Exception {
        when(mockConfigService.getSsmParameter(CORE_VTM_CLAIM)).thenReturn("mock-vtm-claim");

        UserIdentity credentials =
                userIdentityService.generateUserIdentity(
                        USER_ID_1, "test-sub", "P2", emptyContraIndicators);

        assertEquals("mock-vtm-claim", credentials.getVtm());
    }

    @Test
    void generateUserIdentityShouldSetAddressClaimOnUserIdentity() throws Exception {
        List<VcStoreItem> vcStoreItems =
                List.of(
                        createVcStoreItem(
                                USER_ID_1,
                                "ukPassport",
                                VC_PASSPORT_NON_DCMAW_SUCCESSFUL,
                                Instant.now()),
                        createVcStoreItem(USER_ID_1, "fraud", VC_FRAUD_SCORE_1, Instant.now()),
                        createVcStoreItem(USER_ID_1, "kbv", VC_KBV_SCORE_2, Instant.now()),
                        createVcStoreItem(USER_ID_1, "address", VC_ADDRESS_2, Instant.now()));

        when(mockConfigService.getSsmParameter(CORE_VTM_CLAIM)).thenReturn("mock-vtm-claim");
        mockCredentialIssuerConfig();
        when(mockDataStore.getItems(anyString())).thenReturn(vcStoreItems);

        UserIdentity userIdentity =
                userIdentityService.generateUserIdentity(
                        USER_ID_1, "test-sub", "P2", emptyContraIndicators);

        JsonNode userIdentityJsonNode =
                objectMapper.readTree(objectMapper.writeValueAsString(userIdentity));
        JsonNode address = userIdentityJsonNode.get(ADDRESS_CLAIM_NAME).get(0);

        assertEquals("221B", address.get("buildingName").asText());
        assertEquals("BAKER STREET", address.get("streetName").asText());
        assertEquals("LONDON", address.get("addressLocality").asText());
        assertEquals("NW1 6XE", address.get("postalCode").asText());
        assertEquals("1887-01-01", address.get("validFrom").asText());
    }

    @Test
    void generateUserIdentityShouldThrowIfAddressVCIsMissingAddressProperty() {
        List<VcStoreItem> vcStoreItems =
                List.of(
                        createVcStoreItem(
                                USER_ID_1,
                                "ukPassport",
                                VC_PASSPORT_NON_DCMAW_SUCCESSFUL,
                                Instant.now()),
                        createVcStoreItem(USER_ID_1, "fraud", VC_FRAUD_SCORE_1, Instant.now()),
                        createVcStoreItem(USER_ID_1, "kbv", VC_KBV_SCORE_2, Instant.now()),
                        createVcStoreItem(
                                USER_ID_1,
                                "address",
                                VC_ADDRESS_MISSING_ADDRESS_PROPERTY,
                                Instant.now()));

        when(mockConfigService.getSsmParameter(CORE_VTM_CLAIM)).thenReturn("mock-vtm-claim");
        mockCredentialIssuerConfig();
        when(mockDataStore.getItems(anyString())).thenReturn(vcStoreItems);

        HttpResponseExceptionWithErrorBody thrownException =
                assertThrows(
                        HttpResponseExceptionWithErrorBody.class,
                        () ->
                                userIdentityService.generateUserIdentity(
                                        USER_ID_1, "test-sub", "P2", emptyContraIndicators));

        assertEquals(500, thrownException.getResponseCode());
        assertEquals(
                ErrorResponse.FAILED_TO_GENERATE_ADDRESS_CLAIM.getCode(),
                thrownException.getErrorBody().get("error"));
        assertEquals(
                ErrorResponse.FAILED_TO_GENERATE_ADDRESS_CLAIM.getMessage(),
                thrownException.getErrorBody().get("error_description"));
    }

    @Test
    void generateUserIdentityShouldThrowIfAddressVCCanNotBeParsed() {
        List<VcStoreItem> vcStoreItems =
                List.of(
                        createVcStoreItem(
                                USER_ID_1,
                                "ukPassport",
                                VC_PASSPORT_NON_DCMAW_SUCCESSFUL,
                                Instant.now()),
                        createVcStoreItem(USER_ID_1, "fraud", VC_FRAUD_SCORE_1, Instant.now()),
                        createVcStoreItem(USER_ID_1, "kbv", VC_KBV_SCORE_2, Instant.now()),
                        createVcStoreItem(USER_ID_1, "address", "GARBAGE", Instant.now()));

        when(mockConfigService.getSsmParameter(CORE_VTM_CLAIM)).thenReturn("mock-vtm-claim");
        mockCredentialIssuerConfig();
        when(mockDataStore.getItems(anyString())).thenReturn(vcStoreItems);

        assertThrows(
                CredentialParseException.class,
                () ->
                        userIdentityService.generateUserIdentity(
                                USER_ID_1, "test-sub", "P2", emptyContraIndicators));
    }

    @Test
    void shouldNotSetAddressClaimWhenVotIsP0() throws Exception {
        List<VcStoreItem> vcStoreItems =
                List.of(
                        createVcStoreItem(USER_ID_1, "fraud", VC_FRAUD_SCORE_1, Instant.now()),
                        createVcStoreItem(USER_ID_1, "kbv", VC_KBV_SCORE_2, Instant.now()),
                        createVcStoreItem(USER_ID_1, "address", VC_ADDRESS_2, Instant.now()));

        when(mockDataStore.getItems(anyString())).thenReturn(vcStoreItems);

        UserIdentity credentials =
                userIdentityService.generateUserIdentity(
                        USER_ID_1, "test-sub", "P0", emptyContraIndicators);

        assertNull(credentials.getAddressClaim());
    }

    @Test
    void shouldReturnListOfVcsForSharedAttributes() {
        List<VcStoreItem> vcStoreItems =
                List.of(
                        createVcStoreItem(
                                USER_ID_1,
                                "ukPassport",
                                VC_PASSPORT_NON_DCMAW_SUCCESSFUL,
                                Instant.now()),
                        createVcStoreItem(USER_ID_1, "fraud", VC_FRAUD_SCORE_1, Instant.now()));

        when(mockDataStore.getItems(anyString())).thenReturn(vcStoreItems);

        List<String> vcList = userIdentityService.getUserIssuedCredentials(USER_ID_1);

        assertEquals(VC_PASSPORT_NON_DCMAW_SUCCESSFUL, vcList.get(0));
        assertEquals(VC_FRAUD_SCORE_1, vcList.get(1));
    }

    @Test
    void shouldDeleteAllExistingVCs() {
        List<VcStoreItem> vcStoreItems =
                List.of(
                        createVcStoreItem(
                                "a-users-id",
                                "ukPassport",
                                VC_PASSPORT_NON_DCMAW_SUCCESSFUL,
                                Instant.now()),
                        createVcStoreItem("a-users-id", "fraud", VC_FRAUD_SCORE_1, Instant.now()),
                        createVcStoreItem("a-users-id", "sausages", VC_KBV_SCORE_2, Instant.now()));

        when(mockDataStore.getItems("a-users-id")).thenReturn(vcStoreItems);

        userIdentityService.deleteVcStoreItems("a-users-id");

        verify(mockDataStore).delete("a-users-id", "ukPassport");
        verify(mockDataStore).delete("a-users-id", "fraud");
        verify(mockDataStore).delete("a-users-id", "sausages");
    }

    @Test
    void shouldReturnCredentialIssuersFromDataStoreForSpecificUserId() {
        String userId = "userId";
        String testCredentialIssuer = "ukPassport";
        List<VcStoreItem> credentialItem =
                List.of(
                        createVcStoreItem(
                                USER_ID_1,
                                testCredentialIssuer,
                                VC_PASSPORT_NON_DCMAW_SUCCESSFUL,
                                Instant.now()));

        when(mockDataStore.getItems(userId)).thenReturn(credentialItem);

        var vcStoreItems = userIdentityService.getVcStoreItems(userId);

        assertTrue(
                vcStoreItems.stream()
                        .map(VcStoreItem::getCredentialIssuer)
                        .anyMatch(testCredentialIssuer::equals));
    }

    @Test
    void shouldSetDrivingPermitClaimWhenVotIsP2() throws Exception {
        List<VcStoreItem> vcStoreItems =
                List.of(
                        createVcStoreItem(
                                USER_ID_1, "dcmaw", VC_DRIVING_PERMIT_DCMAW, Instant.now()),
                        createVcStoreItem(USER_ID_1, "fraud", VC_FRAUD_SCORE_1, Instant.now()),
                        createVcStoreItem(USER_ID_1, "address", VC_ADDRESS, Instant.now()));

        when(mockConfigService.getSsmParameter(CORE_VTM_CLAIM)).thenReturn("mock-vtm-claim");
        mockCredentialIssuerConfig();
        when(mockDataStore.getItems(anyString())).thenReturn(vcStoreItems);

        UserIdentity credentials =
                userIdentityService.generateUserIdentity(
                        USER_ID_1, "test-sub", "P2", emptyContraIndicators);

        JsonNode drivingPermitClaim = credentials.getDrivingPermitClaim();

        assertEquals("MORGA753116SM9IJ", drivingPermitClaim.get(0).get("personalNumber").asText());
        assertEquals("123456", drivingPermitClaim.get(0).get("issueNumber").asText());
        assertEquals("2023-01-18", drivingPermitClaim.get(0).get("expiryDate").asText());
    }

    @Test
    void shouldNotSetDrivingPermitClaimWhenVotIsP0() throws Exception {
        List<VcStoreItem> vcStoreItems =
                List.of(
                        createVcStoreItem(
                                USER_ID_1, "dcmaw", VC_DRIVING_PERMIT_DCMAW, Instant.now()),
                        createVcStoreItem(USER_ID_1, "fraud", VC_FRAUD_SCORE_1, Instant.now()),
                        createVcStoreItem(USER_ID_1, "address", VC_ADDRESS, Instant.now()));

        when(mockDataStore.getItems(anyString())).thenReturn(vcStoreItems);

        UserIdentity credentials =
                userIdentityService.generateUserIdentity(
                        USER_ID_1, "test-sub", "P0", emptyContraIndicators);

        JsonNode drivingPermitClaim = credentials.getDrivingPermitClaim();

        assertNull(drivingPermitClaim);
    }

    @Test
    void shouldNotSetDrivingPermitClaimWhenDrivingPermitVCIsMissing() throws Exception {
        List<VcStoreItem> vcStoreItems =
                List.of(
                        createVcStoreItem(
                                USER_ID_1,
                                "ukPassport",
                                VC_PASSPORT_NON_DCMAW_SUCCESSFUL,
                                Instant.now()),
                        createVcStoreItem(USER_ID_1, "fraud", VC_FRAUD_SCORE_1, Instant.now()),
                        createVcStoreItem(USER_ID_1, "kbv", VC_KBV_SCORE_2, Instant.now()),
                        createVcStoreItem(USER_ID_1, "address", VC_ADDRESS, Instant.now()));

        when(mockConfigService.getSsmParameter(CORE_VTM_CLAIM)).thenReturn("mock-vtm-claim");
        mockCredentialIssuerConfig();
        when(mockDataStore.getItems(anyString())).thenReturn(vcStoreItems);

        UserIdentity credentials =
                userIdentityService.generateUserIdentity(
                        USER_ID_1, "test-sub", "P2", emptyContraIndicators);

        JsonNode drivingPermitClaim = credentials.getDrivingPermitClaim();

        assertNull(drivingPermitClaim);
    }

    @Test
    void shouldNotSetDrivingPermitClaimWhenDrivingPermitVCFailed() throws Exception {
        List<VcStoreItem> vcStoreItems =
                List.of(
                        createVcStoreItem(
                                USER_ID_1, "dcmaw", VC_DRIVING_PERMIT_DCMAW_FAILED, Instant.now()),
                        createVcStoreItem(
                                USER_ID_1,
                                "ukPassport",
                                VC_PASSPORT_NON_DCMAW_SUCCESSFUL,
                                Instant.now()),
                        createVcStoreItem(USER_ID_1, "fraud", VC_FRAUD_SCORE_1, Instant.now()),
                        createVcStoreItem(USER_ID_1, "address", VC_ADDRESS, Instant.now()),
                        createVcStoreItem(USER_ID_1, "kbv", VC_KBV_SCORE_2, Instant.now()));

        when(mockConfigService.getSsmParameter(CORE_VTM_CLAIM)).thenReturn("mock-vtm-claim");
        mockCredentialIssuerConfig();
        when(mockDataStore.getItems(anyString())).thenReturn(vcStoreItems);

        UserIdentity credentials =
                userIdentityService.generateUserIdentity(
                        USER_ID_1, "test-sub", "P2", emptyContraIndicators);

        JsonNode drivingPermitClaim = credentials.getDrivingPermitClaim();

        assertNull(drivingPermitClaim);
    }

    @Test
    void shouldReturnEmptyWhenMissingDrivingPermitProperty() throws Exception {
        List<VcStoreItem> vcStoreItems =
                List.of(
                        createVcStoreItem(
                                USER_ID_1,
                                "dcmaw",
                                VC_DRIVING_PERMIT_DCMAW_MISSING_DRIVING_PERMIT_PROPERTY,
                                Instant.now()));

        when(mockConfigService.getSsmParameter(CORE_VTM_CLAIM)).thenReturn("mock-vtm-claim");
        mockCredentialIssuerConfig();
        when(mockDataStore.getItems(anyString())).thenReturn(vcStoreItems);

        UserIdentity credentials =
                userIdentityService.generateUserIdentity(
                        USER_ID_1, "test-sub", "P2", emptyContraIndicators);

        assertNull(credentials.getDrivingPermitClaim());
    }

    @Test
    void generateUserIdentityShouldThrowIfDcmawVCCanNotBeParsed() {
        List<VcStoreItem> vcStoreItems =
                List.of(
                        createVcStoreItem(
                                USER_ID_1,
                                "ukPassport",
                                VC_PASSPORT_NON_DCMAW_SUCCESSFUL,
                                Instant.now()),
                        createVcStoreItem(USER_ID_1, "fraud", VC_FRAUD_SCORE_1, Instant.now()),
                        createVcStoreItem(USER_ID_1, "kbv", VC_KBV_SCORE_2, Instant.now()),
                        createVcStoreItem(USER_ID_1, "address", VC_ADDRESS_2, Instant.now()),
                        createVcStoreItem(USER_ID_1, "dcmaw", "GARBAGE", Instant.now()));

        when(mockConfigService.getSsmParameter(CORE_VTM_CLAIM)).thenReturn("mock-vtm-claim");
        mockCredentialIssuerConfig();
        when(mockDataStore.getItems(anyString())).thenReturn(vcStoreItems);

        CredentialParseException thrownException =
                assertThrows(
                        CredentialParseException.class,
                        () ->
                                userIdentityService.generateUserIdentity(
                                        USER_ID_1, "test-sub", "P2", emptyContraIndicators));
        assertEquals(
                "Encountered a parsing error while attempting to parse successful VC Store items.",
                thrownException.getMessage());
    }

    @Test
    void generateUserIdentityShouldSetExitCodeWhenP2AndAlwaysRequiredCiPresent() throws Exception {
        when(mockConfigService.getSsmParameter(CORE_VTM_CLAIM)).thenReturn("mock-vtm-claim");
        when(mockDataStore.getItems(anyString())).thenReturn(List.of());
        when(mockConfigService.enabled(EXIT_CODES)).thenReturn(true);
        when(mockConfigService.getContraIndicatorConfigMap())
                .thenReturn(
                        Map.of(
                                "X01", new ContraIndicatorConfig("X01", 4, -3, "1"),
                                "X02", new ContraIndicatorConfig("X02", 4, -3, "2"),
                                "Z03", new ContraIndicatorConfig("Z03", 4, -3, "3")));
        when(mockConfigService.getSsmParameter(ALWAYS_REQUIRED_EXIT_CODES)).thenReturn("1");

        ContraIndicators contraIndicators =
                ContraIndicators.builder()
                        .contraIndicatorsMap(
                                Map.of(
                                        "X01", ContraIndicator.builder().code("X01").build(),
                                        "X02", ContraIndicator.builder().code("X02").build(),
                                        "Z03", ContraIndicator.builder().code("Z03").build()))
                        .build();

        UserIdentity userIdentity =
                userIdentityService.generateUserIdentity(
                        USER_ID_1, "test-sub", "P2", contraIndicators);

        assertEquals(List.of("1"), userIdentity.getExitCode());
    }

    @Test
    void generateUserIdentityShouldSetEmptyExitCodeWhenP2AndAlwaysRequiredCiNotPresent()
            throws Exception {
        when(mockConfigService.getSsmParameter(CORE_VTM_CLAIM)).thenReturn("mock-vtm-claim");
        when(mockConfigService.enabled(EXIT_CODES)).thenReturn(true);
        when(mockConfigService.getSsmParameter(ALWAYS_REQUIRED_EXIT_CODES)).thenReturn("1");

        UserIdentity userIdentity =
                userIdentityService.generateUserIdentity(
                        USER_ID_1, "test-sub", "P2", emptyContraIndicators);

        assertEquals(List.of(), userIdentity.getExitCode());
    }

    @Test
    void generateUserIdentityShouldThrowWhenP2AndCiCodeNotFound() {
        when(mockConfigService.getSsmParameter(CORE_VTM_CLAIM)).thenReturn("mock-vtm-claim");
        when(mockConfigService.enabled(EXIT_CODES)).thenReturn(true);

        when(mockConfigService.getContraIndicatorConfigMap())
                .thenReturn(Map.of("X01", new ContraIndicatorConfig("X01", 4, -3, "1")));

        ContraIndicators contraIndicators =
                ContraIndicators.builder()
                        .contraIndicatorsMap(
                                Map.of("wat", ContraIndicator.builder().code("wat").build()))
                        .build();

        assertThrows(
                UnrecognisedCiException.class,
                () ->
                        userIdentityService.generateUserIdentity(
                                USER_ID_1, "test-sub", "P2", contraIndicators));
    }

    @Test
    void generateUserIdentityShouldNotSetExitCodeWhenP2AndExitCodesNotEnabled() throws Exception {
        when(mockConfigService.getSsmParameter(CORE_VTM_CLAIM)).thenReturn("mock-vtm-claim");
        when(mockConfigService.enabled(EXIT_CODES)).thenReturn(false);

        UserIdentity userIdentity =
                userIdentityService.generateUserIdentity(
                        USER_ID_1, "test-sub", "P2", emptyContraIndicators);

        assertNull(userIdentity.getExitCode());
    }

    @Test
    void generateUserIdentityShouldSetExitCodeWhenBreachingCiThreshold() throws Exception {
        when(mockConfigService.getSsmParameter(CORE_VTM_CLAIM)).thenReturn("mock-vtm-claim");
        when(mockConfigService.enabled(EXIT_CODES)).thenReturn(true);
        when(mockConfigService.getContraIndicatorConfigMap())
                .thenReturn(
                        Map.of(
                                "X01", new ContraIndicatorConfig("X01", 4, -3, "1"),
                                "X02", new ContraIndicatorConfig("X02", 4, -3, "2"),
                                "Z03", new ContraIndicatorConfig("Z03", 4, -3, "3")));
        when(mockConfigService.getSsmParameter(CI_SCORING_THRESHOLD)).thenReturn("1");

        ContraIndicators contraIndicators =
                ContraIndicators.builder()
                        .contraIndicatorsMap(
                                Map.of(
                                        "X01", ContraIndicator.builder().code("X01").build(),
                                        "X02",
                                                ContraIndicator.builder()
                                                        .code("X02")
                                                        .mitigation(
                                                                List.of(
                                                                        Mitigation.builder()
                                                                                .code("M01")
                                                                                .build()))
                                                        .build(),
                                        "Z03", ContraIndicator.builder().code("Z03").build()))
                        .build();

        UserIdentity userIdentity =
                userIdentityService.generateUserIdentity(
                        USER_ID_1, "test-sub", "P0", contraIndicators);

        assertEquals(List.of("1", "2", "3"), userIdentity.getExitCode());
    }

    @Test
    void generateUserIdentityShouldThrowWhenBreachingAndCiCodeNotFound() {
        when(mockConfigService.getSsmParameter(CORE_VTM_CLAIM)).thenReturn("mock-vtm-claim");
        when(mockConfigService.enabled(EXIT_CODES)).thenReturn(true);
        when(mockConfigService.getContraIndicatorConfigMap())
                .thenReturn(Map.of("X01", new ContraIndicatorConfig("X01", 4, -3, "1")));

        ContraIndicators contraIndicators =
                ContraIndicators.builder()
                        .contraIndicatorsMap(
                                Map.of("wat", ContraIndicator.builder().code("wat").build()))
                        .build();

        assertThrows(
                UnrecognisedCiException.class,
                () ->
                        userIdentityService.generateUserIdentity(
                                USER_ID_1, "test-sub", "P0", contraIndicators));
    }

    @Test
    void generateUserIdentityShouldDeduplicateExitCodes() throws Exception {
        when(mockConfigService.getSsmParameter(CORE_VTM_CLAIM)).thenReturn("mock-vtm-claim");
        when(mockConfigService.enabled(EXIT_CODES)).thenReturn(true);
        when(mockConfigService.getContraIndicatorConfigMap())
                .thenReturn(
                        Map.of(
                                "X01", new ContraIndicatorConfig("X01", 4, -3, "1"),
                                "X02", new ContraIndicatorConfig("X02", 4, -3, "2"),
                                "Z03", new ContraIndicatorConfig("Z03", 4, -3, "3"),
                                "Z04", new ContraIndicatorConfig("Z04", 4, -3, "2")));
        when(mockConfigService.getSsmParameter(CI_SCORING_THRESHOLD)).thenReturn("1");

        ContraIndicators contraIndicators =
                ContraIndicators.builder()
                        .contraIndicatorsMap(
                                Map.of(
                                        "X01", ContraIndicator.builder().code("X01").build(),
                                        "X02", ContraIndicator.builder().code("X02").build(),
                                        "Z03", ContraIndicator.builder().code("Z03").build(),
                                        "Z04", ContraIndicator.builder().code("Z04").build()))
                        .build();

        UserIdentity userIdentity =
                userIdentityService.generateUserIdentity(
                        USER_ID_1, "test-sub", "P0", contraIndicators);

        assertEquals(List.of("1", "2", "3"), userIdentity.getExitCode());
    }

    @Test
    void generateUserIdentityShouldNotSetExitCodeWhenBreachingCiThresholdAndExitCodesNotEnabled()
            throws Exception {
        when(mockConfigService.getSsmParameter(CORE_VTM_CLAIM)).thenReturn("mock-vtm-claim");
        when(mockConfigService.enabled(EXIT_CODES)).thenReturn(false);

        UserIdentity userIdentity =
                userIdentityService.generateUserIdentity(
                        USER_ID_1, "test-sub", "P0", emptyContraIndicators);

        assertNull(userIdentity.getExitCode());
    }

    @Test
    void getFullNamesFromCredentialsValidateSpecialCharactersSuccessScenarios() {
        List<String> fullNames = List.of("Alice JANE DOE", "AlIce Ja-ne Do-e", "ALiCE JA'-ne Do'e");
        assertTrue(userIdentityService.checkNamesForCorrelation(fullNames));

        fullNames = List.of("SÖŞMİĞë", "sosmige", "SÖŞ-Mİ'Ğe");
        assertTrue(userIdentityService.checkNamesForCorrelation(fullNames));
    }

    @Test
    void getFullNamesFromCredentialsValidateSpecialCharactersFailScenarios() {
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
        List<VcStatusDto> vcStatusDtos =
                List.of(
                        new VcStatusDto("issuer1", true),
                        new VcStatusDto("issuer2", true),
                        new VcStatusDto("issuer3", true));
        assertThrows(
                NoVcStatusForIssuerException.class,
                () -> userIdentityService.isVcSuccessful(vcStatusDtos, "badIssuer"));
    }

    @Test
    void getVCSuccessStatusReturnShouldBeEmpty() throws Exception {
        when(userIdentityService.getVcStoreItem(USER_ID_1, "fraud")).thenReturn(null);

        Optional<Boolean> isValid = userIdentityService.getVCSuccessStatus(USER_ID_1, "fraud");

        assertEquals(Optional.empty(), isValid);
    }

    @Test
    void getVCSuccessStatusReturnShouldBeFalse() throws Exception {
        VcStoreItem vcStoreItem =
                createVcStoreItem(USER_ID_1, "ukPassport", M1A_FAILED_PASSPORT_VC, Instant.now());
        when(userIdentityService.getVcStoreItem(USER_ID_1, "ukPassport")).thenReturn(vcStoreItem);

        Optional<Boolean> isValid = userIdentityService.getVCSuccessStatus(USER_ID_1, "ukPassport");

        assertEquals(Optional.of(false), isValid);
    }

    @Test
    void getVCSuccessStatusReturnShouldBeTrue() throws Exception {
        VcStoreItem vcStoreItem =
                createVcStoreItem(
                        USER_ID_1, "ukPassport", VC_PASSPORT_NON_DCMAW_SUCCESSFUL, Instant.now());
        when(userIdentityService.getVcStoreItem(USER_ID_1, "ukPassport")).thenReturn(vcStoreItem);

        Optional<Boolean> isValid = userIdentityService.getVCSuccessStatus(USER_ID_1, "ukPassport");

        assertEquals(Optional.of(true), isValid);
    }

    @Test
    void getVCSuccessStatusShouldIgnoreCIs() throws Exception {
        VcStoreItem vcStoreItem =
                createVcStoreItem(USER_ID_1, "fraud", VC_FRAUD_WITH_CI, Instant.now());
        when(userIdentityService.getVcStoreItem(USER_ID_1, "fraud")).thenReturn(vcStoreItem);

        Optional<Boolean> isValid = userIdentityService.getVCSuccessStatus(USER_ID_1, "fraud");

        assertEquals(Optional.of(true), isValid);
    }

    private VcStoreItem createVcStoreItem(
            String userId, String credentialIssuer, String credential, Instant dateCreated) {
        VcStoreItem vcStoreItem = new VcStoreItem();
        vcStoreItem.setUserId(userId);
        vcStoreItem.setCredentialIssuer(credentialIssuer);
        vcStoreItem.setCredential(credential);
        vcStoreItem.setDateCreated(dateCreated);
        vcStoreItem.setExpirationTime(dateCreated.plusSeconds(1000L));
        return vcStoreItem;
    }

    private void mockCredentialIssuerConfig() {
        NON_EVIDENCE_CRI_TYPES.forEach(
                credentialIssuer ->
                        when(mockConfigService.getComponentId(credentialIssuer))
                                .thenReturn(credentialIssuer));
    }
}
