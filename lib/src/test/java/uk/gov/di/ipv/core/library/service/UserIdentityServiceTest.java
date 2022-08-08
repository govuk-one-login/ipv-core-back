package uk.gov.di.ipv.core.library.service;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import uk.gov.di.ipv.core.library.domain.ErrorResponse;
import uk.gov.di.ipv.core.library.domain.IdentityClaim;
import uk.gov.di.ipv.core.library.domain.UserIdentity;
import uk.gov.di.ipv.core.library.domain.VectorOfTrust;
import uk.gov.di.ipv.core.library.exceptions.HttpResponseExceptionWithErrorBody;
import uk.gov.di.ipv.core.library.persistence.DataStore;
import uk.gov.di.ipv.core.library.persistence.item.UserIssuedCredentialsItem;

import java.time.LocalDateTime;
import java.util.List;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;
import static uk.gov.di.ipv.core.library.config.ConfigurationVariable.CORE_VTM_CLAIM;
import static uk.gov.di.ipv.core.library.domain.UserIdentity.ADDRESS_CLAIM_NAME;
import static uk.gov.di.ipv.core.library.domain.VerifiableCredentialConstants.VC_EVIDENCE;
import static uk.gov.di.ipv.core.library.fixtures.TestFixtures.SIGNED_ADDRESS_VC;
import static uk.gov.di.ipv.core.library.fixtures.TestFixtures.SIGNED_ADDRESS_VC_MISSING_ADDRESS_PROPERTY;
import static uk.gov.di.ipv.core.library.fixtures.TestFixtures.SIGNED_PASSPORT_VC_MISSING_BIRTH_DATE;
import static uk.gov.di.ipv.core.library.fixtures.TestFixtures.SIGNED_PASSPORT_VC_MISSING_NAME;
import static uk.gov.di.ipv.core.library.fixtures.TestFixtures.SIGNED_PASSPORT_VC_MISSING_PASSPORT;
import static uk.gov.di.ipv.core.library.fixtures.TestFixtures.SIGNED_VC_1;
import static uk.gov.di.ipv.core.library.fixtures.TestFixtures.SIGNED_VC_2;
import static uk.gov.di.ipv.core.library.fixtures.TestFixtures.SIGNED_VC_3;
import static uk.gov.di.ipv.core.library.fixtures.TestFixtures.SIGNED_VC_4;
import static uk.gov.di.ipv.core.library.helpers.VerifiableCredentialGenerator.generateVerifiableCredential;
import static uk.gov.di.ipv.core.library.helpers.VerifiableCredentialGenerator.vcClaim;

@ExtendWith(MockitoExtension.class)
class UserIdentityServiceTest {

    private static final ObjectMapper objectMapper = new ObjectMapper();

    @Mock private ConfigurationService mockConfigurationService;

    @Mock private DataStore<UserIssuedCredentialsItem> mockDataStore;

    private UserIdentityService userIdentityService;

    @BeforeEach
    void setUp() {
        userIdentityService = new UserIdentityService(mockConfigurationService, mockDataStore);
    }

    @Test
    void shouldReturnCredentialsFromDataStore() throws HttpResponseExceptionWithErrorBody {
        List<UserIssuedCredentialsItem> userIssuedCredentialsItemList =
                List.of(
                        createUserIssuedCredentialsItem(
                                "user-id-1", "ukPassport", SIGNED_VC_1, LocalDateTime.now()),
                        createUserIssuedCredentialsItem(
                                "user-id-1", "fraud", SIGNED_VC_2, LocalDateTime.now()));

        when(mockDataStore.getItems(anyString())).thenReturn(userIssuedCredentialsItemList);

        UserIdentity credentials =
                userIdentityService.generateUserIdentity("user-id-1", "test-sub");

        assertEquals(SIGNED_VC_1, credentials.getVcs().get(0));
        assertEquals(SIGNED_VC_2, credentials.getVcs().get(1));
        assertEquals("test-sub", credentials.getSub());
    }

    @Test
    void shouldReturnCredentialFromDataStoreForSpecificCri() {
        String ipvSessionId = "ipvSessionId";
        String criId = "criId";
        UserIssuedCredentialsItem credentialItem =
                createUserIssuedCredentialsItem(
                        "user-id-1", "ukPassport", SIGNED_VC_1, LocalDateTime.now());

        when(mockDataStore.getItem(ipvSessionId, criId)).thenReturn(credentialItem);

        UserIssuedCredentialsItem retrievedCredentialItem =
                userIdentityService.getUserIssuedCredential(ipvSessionId, criId);

        assertEquals(credentialItem, retrievedCredentialItem);
    }

    @Test
    void shouldReturnDebugCredentialsFromDataStore() {
        List<UserIssuedCredentialsItem> userIssuedCredentialsItemList =
                List.of(
                        createUserIssuedCredentialsItem(
                                "user-id-1",
                                "ukPassport",
                                SIGNED_VC_1,
                                LocalDateTime.parse("2022-01-25T12:28:56.414849")),
                        createUserIssuedCredentialsItem(
                                "user-id-1",
                                "fraud",
                                SIGNED_VC_2,
                                LocalDateTime.parse("2022-01-25T12:28:56.414849")));

        when(mockDataStore.getItems(anyString())).thenReturn(userIssuedCredentialsItemList);

        Map<String, String> credentials =
                userIdentityService.getUserIssuedDebugCredentials("user-id-1");

        assertEquals(
                "{\"attributes\":{\"userId\":\"user-id-1\",\"dateCreated\":\"2022-01-25T12:28:56.414849\"},\"evidence\":{\"validityScore\":2,\"strengthScore\":4,\"txn\":\"1e0f28c5-6329-46f0-bf0e-833cb9b58c9e\",\"type\":\"IdentityCheck\"}}",
                credentials.get("ukPassport"));
        assertEquals(
                "{\"attributes\":{\"userId\":\"user-id-1\",\"dateCreated\":\"2022-01-25T12:28:56.414849\"},\"evidence\":{\"txn\":\"some-uuid\",\"identityFraudScore\":1,\"type\":\"CriStubCheck\"}}",
                credentials.get("fraud"));
    }

    @Test
    void shouldReturnDebugCredentialsFromDataStoreWhenMissingAGpg45Score() throws Exception {
        Map<String, Object> credentialVcClaim = vcClaim(Map.of("test", "test-value"));
        credentialVcClaim.put(VC_EVIDENCE, List.of());
        List<UserIssuedCredentialsItem> userIssuedCredentialsItemList =
                List.of(
                        createUserIssuedCredentialsItem(
                                "user-id-1",
                                "ukPassport",
                                generateVerifiableCredential(credentialVcClaim),
                                LocalDateTime.parse("2022-01-25T12:28:56.414849")),
                        createUserIssuedCredentialsItem(
                                "user-id-1",
                                "fraud",
                                generateVerifiableCredential(credentialVcClaim),
                                LocalDateTime.parse("2022-01-25T12:28:56.414849")));

        when(mockDataStore.getItems(anyString())).thenReturn(userIssuedCredentialsItemList);

        Map<String, String> credentials =
                userIdentityService.getUserIssuedDebugCredentials("user-id-1");

        assertEquals(
                "{\"attributes\":{\"userId\":\"user-id-1\",\"dateCreated\":\"2022-01-25T12:28:56.414849\"}}",
                credentials.get("ukPassport"));
        assertEquals(
                "{\"attributes\":{\"userId\":\"user-id-1\",\"dateCreated\":\"2022-01-25T12:28:56.414849\"}}",
                credentials.get("fraud"));
    }

    @Test
    void shouldReturnDebugCredentialsEvenIfFailingToParseCredentialJson() {
        List<UserIssuedCredentialsItem> userIssuedCredentialsItemList =
                List.of(
                        createUserIssuedCredentialsItem(
                                "user-id-1",
                                "ukPassport",
                                "invalid-verifiable-credential",
                                LocalDateTime.parse("2022-01-25T12:28:56.414849")));

        when(mockDataStore.getItems(anyString())).thenReturn(userIssuedCredentialsItemList);

        Map<String, String> credentials =
                userIdentityService.getUserIssuedDebugCredentials("user-id-1");

        assertEquals(
                "{\"attributes\":{\"userId\":\"user-id-1\",\"dateCreated\":\"2022-01-25T12:28:56.414849\"}}",
                credentials.get("ukPassport"));
    }

    @Test
    void shouldReturnDebugCredentialsEvenIfFailingToParseGpg45ScoreParamFromJson()
            throws Exception {
        Map<String, Object> credentialVcClaim = vcClaim(Map.of("test", "test-value"));
        credentialVcClaim.put(VC_EVIDENCE, "This should be a list of objects...");
        List<UserIssuedCredentialsItem> userIssuedCredentialsItemList =
                List.of(
                        createUserIssuedCredentialsItem(
                                "user-id-1",
                                "ukPassport",
                                generateVerifiableCredential(credentialVcClaim),
                                LocalDateTime.parse("2022-01-25T12:28:56.414849")));

        when(mockDataStore.getItems(anyString())).thenReturn(userIssuedCredentialsItemList);

        Map<String, String> credentials =
                userIdentityService.getUserIssuedDebugCredentials("user-id-1");

        assertEquals(
                "{\"attributes\":{\"userId\":\"user-id-1\",\"dateCreated\":\"2022-01-25T12:28:56.414849\"}}",
                credentials.get("ukPassport"));
    }

    @Test
    void shouldSetVotClaimToP2OnSuccessfulIdentityCheck()
            throws HttpResponseExceptionWithErrorBody {
        List<UserIssuedCredentialsItem> userIssuedCredentialsItemList =
                List.of(
                        createUserIssuedCredentialsItem(
                                "user-id-1", "ukPassport", SIGNED_VC_1, LocalDateTime.now()),
                        createUserIssuedCredentialsItem(
                                "user-id-1", "fraud", SIGNED_VC_2, LocalDateTime.now()),
                        createUserIssuedCredentialsItem(
                                "user-id-1", "kbv", SIGNED_VC_3, LocalDateTime.now()),
                        createUserIssuedCredentialsItem(
                                "user-id-1", "address", SIGNED_VC_4, LocalDateTime.now()));

        when(mockDataStore.getItems(anyString())).thenReturn(userIssuedCredentialsItemList);

        UserIdentity credentials =
                userIdentityService.generateUserIdentity("user-id-1", "test-sub");

        assertEquals(VectorOfTrust.P2.toString(), credentials.getVot());
    }

    @Test
    void shouldSetVotClaimToP0OnMissingRequiredVC() throws HttpResponseExceptionWithErrorBody {
        List<UserIssuedCredentialsItem> userIssuedCredentialsItemList =
                List.of(
                        createUserIssuedCredentialsItem(
                                "user-id-1", "ukPassport", SIGNED_VC_1, LocalDateTime.now()),
                        createUserIssuedCredentialsItem(
                                "user-id-1", "fraud", SIGNED_VC_2, LocalDateTime.now()));

        when(mockDataStore.getItems(anyString())).thenReturn(userIssuedCredentialsItemList);

        UserIdentity credentials =
                userIdentityService.generateUserIdentity("user-id-1", "test-sub");

        assertEquals(VectorOfTrust.P0.toString(), credentials.getVot());
    }

    @Test
    void shouldSetIdentityClaimWhenVotIsP2() throws HttpResponseExceptionWithErrorBody, Exception {
        List<UserIssuedCredentialsItem> userIssuedCredentialsItemList =
                List.of(
                        createUserIssuedCredentialsItem(
                                "user-id-1", "ukPassport", SIGNED_VC_1, LocalDateTime.now()),
                        createUserIssuedCredentialsItem(
                                "user-id-1", "fraud", SIGNED_VC_2, LocalDateTime.now()),
                        createUserIssuedCredentialsItem(
                                "user-id-1", "kbv", SIGNED_VC_3, LocalDateTime.now()),
                        createUserIssuedCredentialsItem(
                                "user-id-1", "address", SIGNED_VC_4, LocalDateTime.now()));

        when(mockDataStore.getItems(anyString())).thenReturn(userIssuedCredentialsItemList);

        UserIdentity credentials =
                userIdentityService.generateUserIdentity("user-id-1", "test-sub");

        IdentityClaim identityClaim = credentials.getIdentityClaim();

        assertEquals("GivenName", identityClaim.getName().get(0).getNameParts().get(0).getType());
        assertEquals("Paul", identityClaim.getName().get(0).getNameParts().get(0).getValue());

        assertEquals("2020-02-03", identityClaim.getBirthDate().get(0).getValue());
    }

    @Test
    void shouldNotSetIdentityClaimWhenVotIsP0() throws HttpResponseExceptionWithErrorBody {
        List<UserIssuedCredentialsItem> userIssuedCredentialsItemList =
                List.of(
                        createUserIssuedCredentialsItem(
                                "user-id-1", "ukPassport", SIGNED_VC_1, LocalDateTime.now()),
                        createUserIssuedCredentialsItem(
                                "user-id-1", "fraud", SIGNED_VC_2, LocalDateTime.now()));

        when(mockDataStore.getItems(anyString())).thenReturn(userIssuedCredentialsItemList);

        UserIdentity credentials =
                userIdentityService.generateUserIdentity("user-id-1", "test-sub");

        assertNull(credentials.getIdentityClaim());
    }

    @Test
    void shouldThrowExceptionWhenMissingNameProperty() {
        List<UserIssuedCredentialsItem> userIssuedCredentialsItemList =
                List.of(
                        createUserIssuedCredentialsItem(
                                "user-id-1",
                                "ukPassport",
                                SIGNED_PASSPORT_VC_MISSING_NAME,
                                LocalDateTime.now()),
                        createUserIssuedCredentialsItem(
                                "user-id-1", "fraud", SIGNED_VC_2, LocalDateTime.now()),
                        createUserIssuedCredentialsItem(
                                "user-id-1", "kbv", SIGNED_VC_3, LocalDateTime.now()));

        when(mockDataStore.getItems(anyString())).thenReturn(userIssuedCredentialsItemList);

        HttpResponseExceptionWithErrorBody thrownError =
                assertThrows(
                        HttpResponseExceptionWithErrorBody.class,
                        () -> userIdentityService.generateUserIdentity("user-id-1", "test-sub"));

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
        List<UserIssuedCredentialsItem> userIssuedCredentialsItemList =
                List.of(
                        createUserIssuedCredentialsItem(
                                "user-id-1",
                                "ukPassport",
                                SIGNED_PASSPORT_VC_MISSING_BIRTH_DATE,
                                LocalDateTime.now()),
                        createUserIssuedCredentialsItem(
                                "user-id-1", "fraud", SIGNED_VC_2, LocalDateTime.now()),
                        createUserIssuedCredentialsItem(
                                "user-id-1", "kbv", SIGNED_VC_3, LocalDateTime.now()));

        when(mockDataStore.getItems(anyString())).thenReturn(userIssuedCredentialsItemList);

        HttpResponseExceptionWithErrorBody thrownError =
                assertThrows(
                        HttpResponseExceptionWithErrorBody.class,
                        () -> userIdentityService.generateUserIdentity("user-id-1", "test-sub"));

        assertEquals(500, thrownError.getResponseCode());
        assertEquals(
                ErrorResponse.FAILED_TO_GENERATE_IDENTIY_CLAIM.getCode(),
                thrownError.getErrorBody().get("error"));
        assertEquals(
                ErrorResponse.FAILED_TO_GENERATE_IDENTIY_CLAIM.getMessage(),
                thrownError.getErrorBody().get("error_description"));
    }

    @Test
    void shouldSetPassportClaimWhenVotIsP2() throws HttpResponseExceptionWithErrorBody {
        List<UserIssuedCredentialsItem> userIssuedCredentialsItemList =
                List.of(
                        createUserIssuedCredentialsItem(
                                "user-id-1", "ukPassport", SIGNED_VC_1, LocalDateTime.now()),
                        createUserIssuedCredentialsItem(
                                "user-id-1", "fraud", SIGNED_VC_2, LocalDateTime.now()),
                        createUserIssuedCredentialsItem(
                                "user-id-1", "kbv", SIGNED_VC_3, LocalDateTime.now()),
                        createUserIssuedCredentialsItem(
                                "user-id-1", "address", SIGNED_VC_4, LocalDateTime.now()));

        when(mockDataStore.getItems(anyString())).thenReturn(userIssuedCredentialsItemList);

        UserIdentity credentials =
                userIdentityService.generateUserIdentity("user-id-1", "test-sub");

        JsonNode passportClaim = credentials.getPassportClaim();

        assertEquals("123456789", passportClaim.get(0).get("documentNumber").asText());
        assertEquals("2020-01-01", passportClaim.get(0).get("expiryDate").asText());
    }

    @Test
    void shouldNotSetPassportClaimWhenVotIsP0() throws HttpResponseExceptionWithErrorBody {
        List<UserIssuedCredentialsItem> userIssuedCredentialsItemList =
                List.of(
                        createUserIssuedCredentialsItem(
                                "user-id-1", "ukPassport", SIGNED_VC_1, LocalDateTime.now()),
                        createUserIssuedCredentialsItem(
                                "user-id-1", "fraud", SIGNED_VC_2, LocalDateTime.now()));

        when(mockDataStore.getItems(anyString())).thenReturn(userIssuedCredentialsItemList);

        UserIdentity credentials =
                userIdentityService.generateUserIdentity("user-id-1", "test-sub");

        assertNull(credentials.getPassportClaim());
    }

    @Test
    void shouldThrowExceptionWhenMissingPassportProperty() {
        List<UserIssuedCredentialsItem> userIssuedCredentialsItemList =
                List.of(
                        createUserIssuedCredentialsItem(
                                "user-id-1",
                                "ukPassport",
                                SIGNED_PASSPORT_VC_MISSING_PASSPORT,
                                LocalDateTime.now()),
                        createUserIssuedCredentialsItem(
                                "user-id-1", "fraud", SIGNED_VC_2, LocalDateTime.now()),
                        createUserIssuedCredentialsItem(
                                "user-id-1", "kbv", SIGNED_VC_3, LocalDateTime.now()),
                        createUserIssuedCredentialsItem(
                                "user-id-1", "address", SIGNED_VC_4, LocalDateTime.now()));

        when(mockDataStore.getItems(anyString())).thenReturn(userIssuedCredentialsItemList);

        HttpResponseExceptionWithErrorBody thrownError =
                assertThrows(
                        HttpResponseExceptionWithErrorBody.class,
                        () -> userIdentityService.generateUserIdentity("user-id-1", "test-sub"));

        assertEquals(500, thrownError.getResponseCode());
        assertEquals(
                ErrorResponse.FAILED_TO_GENERATE_PASSPORT_CLAIM.getCode(),
                thrownError.getErrorBody().get("error"));
        assertEquals(
                ErrorResponse.FAILED_TO_GENERATE_PASSPORT_CLAIM.getMessage(),
                thrownError.getErrorBody().get("error_description"));
    }

    @Test
    void shouldSetSubClaimOnUserIdentity() throws HttpResponseExceptionWithErrorBody {
        when(mockConfigurationService.getSsmParameter(CORE_VTM_CLAIM)).thenReturn("mock-vtm-claim");

        UserIdentity credentials =
                userIdentityService.generateUserIdentity("user-id-1", "test-sub");

        assertEquals("test-sub", credentials.getSub());
    }

    @Test
    void shouldSetVotClaimToP0OnFailedIdentityCheck() throws HttpResponseExceptionWithErrorBody {
        List<UserIssuedCredentialsItem> userIssuedCredentialsItemList =
                List.of(
                        createUserIssuedCredentialsItem(
                                "user-id-1", "ukPassport", SIGNED_VC_1, LocalDateTime.now()),
                        createUserIssuedCredentialsItem(
                                "user-id-1", "fraud", SIGNED_VC_2, LocalDateTime.now()),
                        createUserIssuedCredentialsItem(
                                "user-id-1", "kbv", SIGNED_VC_4, LocalDateTime.now()));

        when(mockDataStore.getItems(anyString())).thenReturn(userIssuedCredentialsItemList);

        UserIdentity credentials =
                userIdentityService.generateUserIdentity("user-id-1", "test-sub");

        assertEquals(VectorOfTrust.P0.toString(), credentials.getVot());
    }

    @Test
    void shouldSetVtmClaimOnUserIdentity() throws HttpResponseExceptionWithErrorBody {
        when(mockConfigurationService.getSsmParameter(CORE_VTM_CLAIM)).thenReturn("mock-vtm-claim");

        UserIdentity credentials =
                userIdentityService.generateUserIdentity("user-id-1", "test-sub");

        assertEquals("mock-vtm-claim", credentials.getVtm());
    }

    @Test
    void generateUserIdentityShouldSetAddressClaimOnUserIdentity()
            throws Exception, HttpResponseExceptionWithErrorBody {
        List<UserIssuedCredentialsItem> userIssuedCredentialsItemList =
                List.of(
                        createUserIssuedCredentialsItem(
                                "user-id-1", "ukPassport", SIGNED_VC_1, LocalDateTime.now()),
                        createUserIssuedCredentialsItem(
                                "user-id-1", "fraud", SIGNED_VC_2, LocalDateTime.now()),
                        createUserIssuedCredentialsItem(
                                "user-id-1", "kbv", SIGNED_VC_3, LocalDateTime.now()),
                        createUserIssuedCredentialsItem(
                                "user-id-1", "address", SIGNED_ADDRESS_VC, LocalDateTime.now()));

        when(mockDataStore.getItems(anyString())).thenReturn(userIssuedCredentialsItemList);

        UserIdentity userIdentity =
                userIdentityService.generateUserIdentity("user-id-1", "test-sub");

        JsonNode userIdentityJsonNode =
                objectMapper.readTree(objectMapper.writeValueAsString(userIdentity));
        JsonNode address = userIdentityJsonNode.get(ADDRESS_CLAIM_NAME).get(0);

        assertEquals(
                "PRIME MINISTER & FIRST LORD OF THE TREASURY",
                address.get("organisationName").asText());
        assertEquals("10", address.get("buildingNumber").asText());
        assertEquals("DOWNING STREET", address.get("streetName").asText());
        assertEquals("LONDON", address.get("addressLocality").asText());
        assertEquals("SW1A 2AA", address.get("postalCode").asText());
        assertEquals("GB", address.get("addressCountry").asText());
        assertEquals("2019-01-01", address.get("validFrom").asText());
    }

    @Test
    void generateUserIdentityShouldThrowIfAddressVCIsMissingAddressProperty() {
        List<UserIssuedCredentialsItem> userIssuedCredentialsItemList =
                List.of(
                        createUserIssuedCredentialsItem(
                                "user-id-1", "ukPassport", SIGNED_VC_1, LocalDateTime.now()),
                        createUserIssuedCredentialsItem(
                                "user-id-1", "fraud", SIGNED_VC_2, LocalDateTime.now()),
                        createUserIssuedCredentialsItem(
                                "user-id-1", "kbv", SIGNED_VC_3, LocalDateTime.now()),
                        createUserIssuedCredentialsItem(
                                "user-id-1",
                                "address",
                                SIGNED_ADDRESS_VC_MISSING_ADDRESS_PROPERTY,
                                LocalDateTime.now()));

        when(mockDataStore.getItems(anyString())).thenReturn(userIssuedCredentialsItemList);

        HttpResponseExceptionWithErrorBody thrownException =
                assertThrows(
                        HttpResponseExceptionWithErrorBody.class,
                        () -> userIdentityService.generateUserIdentity("user-id-1", "test-sub"));

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
        List<UserIssuedCredentialsItem> userIssuedCredentialsItemList =
                List.of(
                        createUserIssuedCredentialsItem(
                                "user-id-1", "ukPassport", SIGNED_VC_1, LocalDateTime.now()),
                        createUserIssuedCredentialsItem(
                                "user-id-1", "fraud", SIGNED_VC_2, LocalDateTime.now()),
                        createUserIssuedCredentialsItem(
                                "user-id-1", "kbv", SIGNED_VC_3, LocalDateTime.now()),
                        createUserIssuedCredentialsItem(
                                "user-id-1", "address", "GARBAGE", LocalDateTime.now()));

        when(mockDataStore.getItems(anyString())).thenReturn(userIssuedCredentialsItemList);

        HttpResponseExceptionWithErrorBody thrownException =
                assertThrows(
                        HttpResponseExceptionWithErrorBody.class,
                        () -> userIdentityService.generateUserIdentity("user-id-1", "test-sub"));

        assertEquals(500, thrownException.getResponseCode());
        assertEquals(
                ErrorResponse.FAILED_TO_GENERATE_ADDRESS_CLAIM.getCode(),
                thrownException.getErrorBody().get("error"));
        assertEquals(
                ErrorResponse.FAILED_TO_GENERATE_ADDRESS_CLAIM.getMessage(),
                thrownException.getErrorBody().get("error_description"));
    }

    @Test
    void shouldNotSetAddressClaimWhenVotIsP0() throws HttpResponseExceptionWithErrorBody {
        List<UserIssuedCredentialsItem> userIssuedCredentialsItemList =
                List.of(
                        createUserIssuedCredentialsItem(
                                "user-id-1", "fraud", SIGNED_VC_2, LocalDateTime.now()),
                        createUserIssuedCredentialsItem(
                                "user-id-1", "kbv", SIGNED_VC_3, LocalDateTime.now()),
                        createUserIssuedCredentialsItem(
                                "user-id-1", "address", SIGNED_ADDRESS_VC, LocalDateTime.now()));

        when(mockDataStore.getItems(anyString())).thenReturn(userIssuedCredentialsItemList);

        UserIdentity credentials =
                userIdentityService.generateUserIdentity("user-id-1", "test-sub");

        assertNull(credentials.getAddressClaim());
    }

    @Test
    void shouldReturnListOfVcsForSharedAttributes() {
        List<UserIssuedCredentialsItem> userIssuedCredentialsItemList =
                List.of(
                        createUserIssuedCredentialsItem(
                                "user-id-1", "ukPassport", SIGNED_VC_1, LocalDateTime.now()),
                        createUserIssuedCredentialsItem(
                                "user-id-1", "fraud", SIGNED_VC_2, LocalDateTime.now()));

        when(mockDataStore.getItems(anyString())).thenReturn(userIssuedCredentialsItemList);

        List<String> vcList = userIdentityService.getUserIssuedCredentials("user-id-1");

        assertEquals(SIGNED_VC_1, vcList.get(0));
        assertEquals(SIGNED_VC_2, vcList.get(1));
    }

    @Test
    void shouldDeleteAllExistingVCs() {
        List<UserIssuedCredentialsItem> userIssuedCredentialsItemList =
                List.of(
                        createUserIssuedCredentialsItem(
                                "a-users-id", "ukPassport", SIGNED_VC_1, LocalDateTime.now()),
                        createUserIssuedCredentialsItem(
                                "a-users-id", "fraud", SIGNED_VC_2, LocalDateTime.now()),
                        createUserIssuedCredentialsItem(
                                "a-users-id", "sausages", SIGNED_VC_3, LocalDateTime.now()));

        when(mockDataStore.getItems("a-users-id")).thenReturn(userIssuedCredentialsItemList);

        userIdentityService.deleteUserIssuedCredentials("a-users-id");

        verify(mockDataStore).delete("a-users-id", "ukPassport");
        verify(mockDataStore).delete("a-users-id", "fraud");
        verify(mockDataStore).delete("a-users-id", "sausages");
    }

    @Test
    void shouldReturnCredentialIssuersFromDataStoreForSpecificUserId() {
        String userId = "userId";
        String testCredentialIssuer = "ukPassport";
        List<UserIssuedCredentialsItem> credentialItem =
                List.of(
                        createUserIssuedCredentialsItem(
                                "user-id-1",
                                testCredentialIssuer,
                                SIGNED_VC_1,
                                LocalDateTime.now()));

        when(mockDataStore.getItems(userId)).thenReturn(credentialItem);

        List<String> retrievedCredentialItem =
                userIdentityService.getUserIssuedCredentialIssuers(userId);

        assertTrue(
                retrievedCredentialItem.stream()
                        .anyMatch(item -> testCredentialIssuer.equals(item)));
    }

    private UserIssuedCredentialsItem createUserIssuedCredentialsItem(
            String userId, String credentialIssuer, String credential, LocalDateTime dateCreated) {
        UserIssuedCredentialsItem userIssuedCredentialsItem = new UserIssuedCredentialsItem();
        userIssuedCredentialsItem.setUserId(userId);
        userIssuedCredentialsItem.setCredentialIssuer(credentialIssuer);
        userIssuedCredentialsItem.setCredential(credential);
        userIssuedCredentialsItem.setDateCreated(dateCreated);
        return userIssuedCredentialsItem;
    }
}
