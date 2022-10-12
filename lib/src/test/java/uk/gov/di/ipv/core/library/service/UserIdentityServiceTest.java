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
import uk.gov.di.ipv.core.library.dto.CredentialIssuerConfig;
import uk.gov.di.ipv.core.library.dto.VcStatusDto;
import uk.gov.di.ipv.core.library.exceptions.HttpResponseExceptionWithErrorBody;
import uk.gov.di.ipv.core.library.persistence.DataStore;
import uk.gov.di.ipv.core.library.persistence.item.UserIssuedCredentialsItem;

import java.net.URI;
import java.time.Instant;
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
import static uk.gov.di.ipv.core.library.fixtures.TestFixtures.SIGNED_DCMAW_VC;
import static uk.gov.di.ipv.core.library.fixtures.TestFixtures.SIGNED_DCMAW_VC_MISSING_DRIVING_PERMIT_PROPERTY;
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
                                "user-id-1", "ukPassport", SIGNED_VC_1, Instant.now()),
                        createUserIssuedCredentialsItem(
                                "user-id-1", "fraud", SIGNED_VC_2, Instant.now()));

        List<VcStatusDto> currentVcStatuses =
                List.of(new VcStatusDto("test-issuer", true), new VcStatusDto("test-issuer", true));

        when(mockDataStore.getItems(anyString())).thenReturn(userIssuedCredentialsItemList);
        when(mockConfigurationService.getCredentialIssuer(anyString()))
                .thenReturn(
                        new CredentialIssuerConfig(
                                "test-cri",
                                "test cri",
                                URI.create("https://example.com/token"),
                                URI.create("https://example.com/credential"),
                                URI.create("https://example.com/authorize"),
                                "ipv-core",
                                "test-jwk",
                                "test-jwk",
                                "test-issuer",
                                URI.create("https://example.com/callback")));

        UserIdentity credentials =
                userIdentityService.generateUserIdentity(
                        "user-id-1", "test-sub", "P2", currentVcStatuses);

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
                        "user-id-1", "ukPassport", SIGNED_VC_1, Instant.now());

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
                                Instant.parse("2022-01-25T12:28:56.414849Z")),
                        createUserIssuedCredentialsItem(
                                "user-id-1",
                                "fraud",
                                SIGNED_VC_2,
                                Instant.parse("2022-01-25T12:28:56.414849Z")));

        when(mockDataStore.getItems(anyString())).thenReturn(userIssuedCredentialsItemList);

        Map<String, String> credentials =
                userIdentityService.getUserIssuedDebugCredentials("user-id-1");

        assertEquals(
                "{\"attributes\":{\"userId\":\"user-id-1\",\"dateCreated\":\"2022-01-25T12:28:56.414849Z\"},\"evidence\":{\"validityScore\":2,\"strengthScore\":4,\"txn\":\"1e0f28c5-6329-46f0-bf0e-833cb9b58c9e\",\"type\":\"IdentityCheck\"}}",
                credentials.get("ukPassport"));
        assertEquals(
                "{\"attributes\":{\"userId\":\"user-id-1\",\"dateCreated\":\"2022-01-25T12:28:56.414849Z\"},\"evidence\":{\"txn\":\"some-uuid\",\"identityFraudScore\":1,\"type\":\"CriStubCheck\"}}",
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
                                generateVerifiableCredential(
                                        credentialVcClaim, "https://issuer.example.com"),
                                Instant.parse("2022-01-25T12:28:56.414849Z")),
                        createUserIssuedCredentialsItem(
                                "user-id-1",
                                "fraud",
                                generateVerifiableCredential(
                                        credentialVcClaim, "https://issuer.example.com"),
                                Instant.parse("2022-01-25T12:28:56.414849Z")));

        when(mockDataStore.getItems(anyString())).thenReturn(userIssuedCredentialsItemList);

        Map<String, String> credentials =
                userIdentityService.getUserIssuedDebugCredentials("user-id-1");

        assertEquals(
                "{\"attributes\":{\"userId\":\"user-id-1\",\"dateCreated\":\"2022-01-25T12:28:56.414849Z\"}}",
                credentials.get("ukPassport"));
        assertEquals(
                "{\"attributes\":{\"userId\":\"user-id-1\",\"dateCreated\":\"2022-01-25T12:28:56.414849Z\"}}",
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
                                Instant.parse("2022-01-25T12:28:56.414849Z")));

        when(mockDataStore.getItems(anyString())).thenReturn(userIssuedCredentialsItemList);

        Map<String, String> credentials =
                userIdentityService.getUserIssuedDebugCredentials("user-id-1");

        assertEquals(
                "{\"attributes\":{\"userId\":\"user-id-1\",\"dateCreated\":\"2022-01-25T12:28:56.414849Z\"}}",
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
                                generateVerifiableCredential(
                                        credentialVcClaim, "https://issuer.example.com"),
                                Instant.parse("2022-01-25T12:28:56.414849Z")));

        when(mockDataStore.getItems(anyString())).thenReturn(userIssuedCredentialsItemList);

        Map<String, String> credentials =
                userIdentityService.getUserIssuedDebugCredentials("user-id-1");

        assertEquals(
                "{\"attributes\":{\"userId\":\"user-id-1\",\"dateCreated\":\"2022-01-25T12:28:56.414849Z\"}}",
                credentials.get("ukPassport"));
    }

    @Test
    void shouldSetVotClaimToP2OnSuccessfulIdentityCheck()
            throws HttpResponseExceptionWithErrorBody {
        List<UserIssuedCredentialsItem> userIssuedCredentialsItemList =
                List.of(
                        createUserIssuedCredentialsItem(
                                "user-id-1", "ukPassport", SIGNED_VC_1, Instant.now()),
                        createUserIssuedCredentialsItem(
                                "user-id-1", "fraud", SIGNED_VC_2, Instant.now()),
                        createUserIssuedCredentialsItem(
                                "user-id-1", "kbv", SIGNED_VC_3, Instant.now()),
                        createUserIssuedCredentialsItem(
                                "user-id-1", "address", SIGNED_VC_4, Instant.now()));

        List<VcStatusDto> currentVcStatuses =
                List.of(new VcStatusDto("test-issuer", true), new VcStatusDto("test-issuer", true));

        when(mockDataStore.getItems(anyString())).thenReturn(userIssuedCredentialsItemList);
        when(mockConfigurationService.getCredentialIssuer(anyString()))
                .thenReturn(
                        new CredentialIssuerConfig(
                                "test-cri",
                                "test cri",
                                URI.create("https://example.com/token"),
                                URI.create("https://example.com/credential"),
                                URI.create("https://example.com/authorize"),
                                "ipv-core",
                                "test-jwk",
                                "test-jwk",
                                "test-issuer",
                                URI.create("https://example.com/callback")));

        UserIdentity credentials =
                userIdentityService.generateUserIdentity(
                        "user-id-1", "test-sub", "P2", currentVcStatuses);

        assertEquals(VectorOfTrust.P2.toString(), credentials.getVot());
    }

    @Test
    void shouldSetIdentityClaimWhenVotIsP2() throws HttpResponseExceptionWithErrorBody, Exception {
        List<UserIssuedCredentialsItem> userIssuedCredentialsItemList =
                List.of(
                        createUserIssuedCredentialsItem(
                                "user-id-1", "ukPassport", SIGNED_VC_1, Instant.now()),
                        createUserIssuedCredentialsItem(
                                "user-id-1", "fraud", SIGNED_VC_2, Instant.now()),
                        createUserIssuedCredentialsItem(
                                "user-id-1", "kbv", SIGNED_VC_3, Instant.now()),
                        createUserIssuedCredentialsItem(
                                "user-id-1", "address", SIGNED_VC_4, Instant.now()));

        List<VcStatusDto> currentVcStatuses =
                List.of(new VcStatusDto("test-issuer", true), new VcStatusDto("test-issuer", true));

        when(mockDataStore.getItems(anyString())).thenReturn(userIssuedCredentialsItemList);
        when(mockConfigurationService.getCredentialIssuer(anyString()))
                .thenReturn(
                        new CredentialIssuerConfig(
                                "test-cri",
                                "test cri",
                                URI.create("https://example.com/token"),
                                URI.create("https://example.com/credential"),
                                URI.create("https://example.com/authorize"),
                                "ipv-core",
                                "test-jwk",
                                "test-jwk",
                                "test-issuer",
                                URI.create("https://example.com/callback")));

        UserIdentity credentials =
                userIdentityService.generateUserIdentity(
                        "user-id-1", "test-sub", "P2", currentVcStatuses);

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
                                "user-id-1", "ukPassport", SIGNED_VC_1, Instant.now()),
                        createUserIssuedCredentialsItem(
                                "user-id-1", "fraud", SIGNED_VC_2, Instant.now()));

        List<VcStatusDto> currentVcStatuses =
                List.of(new VcStatusDto("test-issuer", true), new VcStatusDto("test-issuer", true));

        when(mockDataStore.getItems(anyString())).thenReturn(userIssuedCredentialsItemList);

        UserIdentity credentials =
                userIdentityService.generateUserIdentity(
                        "user-id-1", "test-sub", "P0", currentVcStatuses);

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
                                Instant.now()),
                        createUserIssuedCredentialsItem(
                                "user-id-1", "fraud", SIGNED_VC_2, Instant.now()),
                        createUserIssuedCredentialsItem(
                                "user-id-1", "kbv", SIGNED_VC_3, Instant.now()));

        List<VcStatusDto> currentVcStatuses =
                List.of(new VcStatusDto("test-issuer", true), new VcStatusDto("test-issuer", true));

        when(mockDataStore.getItems(anyString())).thenReturn(userIssuedCredentialsItemList);
        when(mockConfigurationService.getCredentialIssuer(anyString()))
                .thenReturn(
                        new CredentialIssuerConfig(
                                "test-cri",
                                "test cri",
                                URI.create("https://example.com/token"),
                                URI.create("https://example.com/credential"),
                                URI.create("https://example.com/authorize"),
                                "ipv-core",
                                "test-jwk",
                                "test-jwk",
                                "test-issuer",
                                URI.create("https://example.com/callback")));

        HttpResponseExceptionWithErrorBody thrownError =
                assertThrows(
                        HttpResponseExceptionWithErrorBody.class,
                        () ->
                                userIdentityService.generateUserIdentity(
                                        "user-id-1", "test-sub", "P2", currentVcStatuses));

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
                                Instant.now()),
                        createUserIssuedCredentialsItem(
                                "user-id-1", "fraud", SIGNED_VC_2, Instant.now()),
                        createUserIssuedCredentialsItem(
                                "user-id-1", "kbv", SIGNED_VC_3, Instant.now()));

        List<VcStatusDto> currentVcStatuses =
                List.of(new VcStatusDto("test-issuer", true), new VcStatusDto("test-issuer", true));

        when(mockDataStore.getItems(anyString())).thenReturn(userIssuedCredentialsItemList);
        when(mockConfigurationService.getCredentialIssuer(anyString()))
                .thenReturn(
                        new CredentialIssuerConfig(
                                "test-cri",
                                "test cri",
                                URI.create("https://example.com/token"),
                                URI.create("https://example.com/credential"),
                                URI.create("https://example.com/authorize"),
                                "ipv-core",
                                "test-jwk",
                                "test-jwk",
                                "test-issuer",
                                URI.create("https://example.com/callback")));

        HttpResponseExceptionWithErrorBody thrownError =
                assertThrows(
                        HttpResponseExceptionWithErrorBody.class,
                        () ->
                                userIdentityService.generateUserIdentity(
                                        "user-id-1", "test-sub", "P2", currentVcStatuses));

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
                                "user-id-1", "ukPassport", SIGNED_VC_1, Instant.now()),
                        createUserIssuedCredentialsItem(
                                "user-id-1", "fraud", SIGNED_VC_2, Instant.now()),
                        createUserIssuedCredentialsItem(
                                "user-id-1", "kbv", SIGNED_VC_3, Instant.now()),
                        createUserIssuedCredentialsItem(
                                "user-id-1", "address", SIGNED_VC_4, Instant.now()));

        List<VcStatusDto> currentVcStatuses =
                List.of(new VcStatusDto("test-issuer", true), new VcStatusDto("test-issuer", true));

        when(mockDataStore.getItems(anyString())).thenReturn(userIssuedCredentialsItemList);
        when(mockConfigurationService.getCredentialIssuer(anyString()))
                .thenReturn(
                        new CredentialIssuerConfig(
                                "test-cri",
                                "test cri",
                                URI.create("https://example.com/token"),
                                URI.create("https://example.com/credential"),
                                URI.create("https://example.com/authorize"),
                                "ipv-core",
                                "test-jwk",
                                "test-jwk",
                                "test-issuer",
                                URI.create("https://example.com/callback")));

        UserIdentity credentials =
                userIdentityService.generateUserIdentity(
                        "user-id-1", "test-sub", "P2", currentVcStatuses);

        JsonNode passportClaim = credentials.getPassportClaim();

        assertEquals("123456789", passportClaim.get(0).get("documentNumber").asText());
        assertEquals("2020-01-01", passportClaim.get(0).get("expiryDate").asText());
    }

    @Test
    void shouldNotSetPassportClaimWhenVotIsP0() throws HttpResponseExceptionWithErrorBody {
        List<UserIssuedCredentialsItem> userIssuedCredentialsItemList =
                List.of(
                        createUserIssuedCredentialsItem(
                                "user-id-1", "ukPassport", SIGNED_VC_1, Instant.now()),
                        createUserIssuedCredentialsItem(
                                "user-id-1", "fraud", SIGNED_VC_2, Instant.now()));

        List<VcStatusDto> currentVcStatuses =
                List.of(new VcStatusDto("test-issuer", true), new VcStatusDto("test-issuer", true));

        when(mockDataStore.getItems(anyString())).thenReturn(userIssuedCredentialsItemList);

        UserIdentity credentials =
                userIdentityService.generateUserIdentity(
                        "user-id-1", "test-sub", "P0", currentVcStatuses);

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
                                Instant.now()),
                        createUserIssuedCredentialsItem(
                                "user-id-1", "fraud", SIGNED_VC_2, Instant.now()),
                        createUserIssuedCredentialsItem(
                                "user-id-1", "kbv", SIGNED_VC_3, Instant.now()),
                        createUserIssuedCredentialsItem(
                                "user-id-1", "address", SIGNED_VC_4, Instant.now()));

        List<VcStatusDto> currentVcStatuses =
                List.of(new VcStatusDto("test-issuer", true), new VcStatusDto("test-issuer", true));

        when(mockDataStore.getItems(anyString())).thenReturn(userIssuedCredentialsItemList);
        when(mockConfigurationService.getCredentialIssuer(anyString()))
                .thenReturn(
                        new CredentialIssuerConfig(
                                "test-cri",
                                "test cri",
                                URI.create("https://example.com/token"),
                                URI.create("https://example.com/credential"),
                                URI.create("https://example.com/authorize"),
                                "ipv-core",
                                "test-jwk",
                                "test-jwk",
                                "test-issuer",
                                URI.create("https://example.com/callback")));

        HttpResponseExceptionWithErrorBody thrownError =
                assertThrows(
                        HttpResponseExceptionWithErrorBody.class,
                        () ->
                                userIdentityService.generateUserIdentity(
                                        "user-id-1", "test-sub", "P2", currentVcStatuses));

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

        List<VcStatusDto> currentVcStatuses =
                List.of(new VcStatusDto("test-issuer", true), new VcStatusDto("test-issuer", true));

        UserIdentity credentials =
                userIdentityService.generateUserIdentity(
                        "user-id-1", "test-sub", "P2", currentVcStatuses);

        assertEquals("test-sub", credentials.getSub());
    }

    @Test
    void shouldSetVtmClaimOnUserIdentity() throws HttpResponseExceptionWithErrorBody {
        when(mockConfigurationService.getSsmParameter(CORE_VTM_CLAIM)).thenReturn("mock-vtm-claim");

        List<VcStatusDto> currentVcStatuses =
                List.of(new VcStatusDto("test-issuer", true), new VcStatusDto("test-issuer", true));

        UserIdentity credentials =
                userIdentityService.generateUserIdentity(
                        "user-id-1", "test-sub", "P2", currentVcStatuses);

        assertEquals("mock-vtm-claim", credentials.getVtm());
    }

    @Test
    void generateUserIdentityShouldSetAddressClaimOnUserIdentity()
            throws Exception, HttpResponseExceptionWithErrorBody {
        List<UserIssuedCredentialsItem> userIssuedCredentialsItemList =
                List.of(
                        createUserIssuedCredentialsItem(
                                "user-id-1", "ukPassport", SIGNED_VC_1, Instant.now()),
                        createUserIssuedCredentialsItem(
                                "user-id-1", "fraud", SIGNED_VC_2, Instant.now()),
                        createUserIssuedCredentialsItem(
                                "user-id-1", "kbv", SIGNED_VC_3, Instant.now()),
                        createUserIssuedCredentialsItem(
                                "user-id-1", "address", SIGNED_ADDRESS_VC, Instant.now()));

        List<VcStatusDto> currentVcStatuses =
                List.of(new VcStatusDto("test-issuer", true), new VcStatusDto("test-issuer", true));

        when(mockDataStore.getItems(anyString())).thenReturn(userIssuedCredentialsItemList);
        when(mockConfigurationService.getCredentialIssuer(anyString()))
                .thenReturn(
                        new CredentialIssuerConfig(
                                "test-cri",
                                "test cri",
                                URI.create("https://example.com/token"),
                                URI.create("https://example.com/credential"),
                                URI.create("https://example.com/authorize"),
                                "ipv-core",
                                "test-jwk",
                                "test-jwk",
                                "test-issuer",
                                URI.create("https://example.com/callback")));

        UserIdentity userIdentity =
                userIdentityService.generateUserIdentity(
                        "user-id-1", "test-sub", "P2", currentVcStatuses);

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
                                "user-id-1", "ukPassport", SIGNED_VC_1, Instant.now()),
                        createUserIssuedCredentialsItem(
                                "user-id-1", "fraud", SIGNED_VC_2, Instant.now()),
                        createUserIssuedCredentialsItem(
                                "user-id-1", "kbv", SIGNED_VC_3, Instant.now()),
                        createUserIssuedCredentialsItem(
                                "user-id-1",
                                "address",
                                SIGNED_ADDRESS_VC_MISSING_ADDRESS_PROPERTY,
                                Instant.now()));

        List<VcStatusDto> currentVcStatuses =
                List.of(new VcStatusDto("test-issuer", true), new VcStatusDto("test-issuer", true));

        when(mockDataStore.getItems(anyString())).thenReturn(userIssuedCredentialsItemList);
        when(mockConfigurationService.getCredentialIssuer(anyString()))
                .thenReturn(
                        new CredentialIssuerConfig(
                                "test-cri",
                                "test cri",
                                URI.create("https://example.com/token"),
                                URI.create("https://example.com/credential"),
                                URI.create("https://example.com/authorize"),
                                "ipv-core",
                                "test-jwk",
                                "test-jwk",
                                "test-issuer",
                                URI.create("https://example.com/callback")));

        HttpResponseExceptionWithErrorBody thrownException =
                assertThrows(
                        HttpResponseExceptionWithErrorBody.class,
                        () ->
                                userIdentityService.generateUserIdentity(
                                        "user-id-1", "test-sub", "P2", currentVcStatuses));

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
                                "user-id-1", "ukPassport", SIGNED_VC_1, Instant.now()),
                        createUserIssuedCredentialsItem(
                                "user-id-1", "fraud", SIGNED_VC_2, Instant.now()),
                        createUserIssuedCredentialsItem(
                                "user-id-1", "kbv", SIGNED_VC_3, Instant.now()),
                        createUserIssuedCredentialsItem(
                                "user-id-1", "address", "GARBAGE", Instant.now()));

        List<VcStatusDto> currentVcStatuses =
                List.of(new VcStatusDto("test-issuer", true), new VcStatusDto("test-issuer", true));

        when(mockDataStore.getItems(anyString())).thenReturn(userIssuedCredentialsItemList);
        when(mockConfigurationService.getCredentialIssuer(anyString()))
                .thenReturn(
                        new CredentialIssuerConfig(
                                "test-cri",
                                "test cri",
                                URI.create("https://example.com/token"),
                                URI.create("https://example.com/credential"),
                                URI.create("https://example.com/authorize"),
                                "ipv-core",
                                "test-jwk",
                                "test-jwk",
                                "test-issuer",
                                URI.create("https://example.com/callback")));

        HttpResponseExceptionWithErrorBody thrownException =
                assertThrows(
                        HttpResponseExceptionWithErrorBody.class,
                        () ->
                                userIdentityService.generateUserIdentity(
                                        "user-id-1", "test-sub", "P2", currentVcStatuses));

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
                                "user-id-1", "fraud", SIGNED_VC_2, Instant.now()),
                        createUserIssuedCredentialsItem(
                                "user-id-1", "kbv", SIGNED_VC_3, Instant.now()),
                        createUserIssuedCredentialsItem(
                                "user-id-1", "address", SIGNED_ADDRESS_VC, Instant.now()));

        List<VcStatusDto> currentVcStatuses =
                List.of(new VcStatusDto("test-issuer", true), new VcStatusDto("test-issuer", true));

        when(mockDataStore.getItems(anyString())).thenReturn(userIssuedCredentialsItemList);

        UserIdentity credentials =
                userIdentityService.generateUserIdentity(
                        "user-id-1", "test-sub", "P0", currentVcStatuses);

        assertNull(credentials.getAddressClaim());
    }

    @Test
    void shouldReturnListOfVcsForSharedAttributes() {
        List<UserIssuedCredentialsItem> userIssuedCredentialsItemList =
                List.of(
                        createUserIssuedCredentialsItem(
                                "user-id-1", "ukPassport", SIGNED_VC_1, Instant.now()),
                        createUserIssuedCredentialsItem(
                                "user-id-1", "fraud", SIGNED_VC_2, Instant.now()));

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
                                "a-users-id", "ukPassport", SIGNED_VC_1, Instant.now()),
                        createUserIssuedCredentialsItem(
                                "a-users-id", "fraud", SIGNED_VC_2, Instant.now()),
                        createUserIssuedCredentialsItem(
                                "a-users-id", "sausages", SIGNED_VC_3, Instant.now()));

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
                                "user-id-1", testCredentialIssuer, SIGNED_VC_1, Instant.now()));

        when(mockDataStore.getItems(userId)).thenReturn(credentialItem);

        List<String> retrievedCredentialItem =
                userIdentityService.getUserIssuedCredentialIssuers(userId);

        assertTrue(
                retrievedCredentialItem.stream()
                        .anyMatch(item -> testCredentialIssuer.equals(item)));
    }

    @Test
    void shouldSetDrivingPermitClaimWhenVotIsP2() throws HttpResponseExceptionWithErrorBody {
        List<UserIssuedCredentialsItem> userIssuedCredentialsItemList =
                List.of(
                        createUserIssuedCredentialsItem(
                                "user-id-1", "dcmaw", SIGNED_DCMAW_VC, Instant.now()),
                        createUserIssuedCredentialsItem(
                                "user-id-1", "fraud", SIGNED_VC_2, Instant.now()),
                        createUserIssuedCredentialsItem(
                                "user-id-1", "address", SIGNED_VC_4, Instant.now()));

        List<VcStatusDto> currentVcStatuses =
                List.of(
                        new VcStatusDto("test-issuer", true),
                        new VcStatusDto("dcmaw-issuer", true));

        when(mockDataStore.getItems(anyString())).thenReturn(userIssuedCredentialsItemList);
        when(mockConfigurationService.getCredentialIssuer("dcmaw"))
                .thenReturn(
                        new CredentialIssuerConfig(
                                "test-cri",
                                "test cri",
                                URI.create("https://example.com/token"),
                                URI.create("https://example.com/credential"),
                                URI.create("https://example.com/authorize"),
                                "ipv-core",
                                "test-jwk",
                                "test-jwk",
                                "dcmaw-issuer",
                                URI.create("https://example.com/callback")));

        UserIdentity credentials =
                userIdentityService.generateUserIdentity(
                        "user-id-1", "test-sub", "P2", currentVcStatuses);

        JsonNode drivingPermitClaim = credentials.getDrivingPermitClaim();

        assertEquals("MORGA753116SM9IJ", drivingPermitClaim.get(0).get("personalNumber").asText());
        assertEquals("123456", drivingPermitClaim.get(0).get("issueNumber").asText());
        assertEquals("2022-03-14", drivingPermitClaim.get(0).get("issueDate").asText());
        assertEquals("2023-01-18", drivingPermitClaim.get(0).get("expiryDate").asText());
    }

    @Test
    void shouldNotSetDrivingPermitClaimWhenVotIsP0() throws HttpResponseExceptionWithErrorBody {
        List<UserIssuedCredentialsItem> userIssuedCredentialsItemList =
                List.of(
                        createUserIssuedCredentialsItem(
                                "user-id-1", "dcmaw", SIGNED_DCMAW_VC, Instant.now()),
                        createUserIssuedCredentialsItem(
                                "user-id-1", "fraud", SIGNED_VC_2, Instant.now()),
                        createUserIssuedCredentialsItem(
                                "user-id-1", "address", SIGNED_VC_4, Instant.now()));

        List<VcStatusDto> currentVcStatuses =
                List.of(
                        new VcStatusDto("test-issuer", true),
                        new VcStatusDto("dcmaw-issuer", true));

        when(mockDataStore.getItems(anyString())).thenReturn(userIssuedCredentialsItemList);

        UserIdentity credentials =
                userIdentityService.generateUserIdentity(
                        "user-id-1", "test-sub", "P0", currentVcStatuses);

        JsonNode drivingPermitClaim = credentials.getDrivingPermitClaim();

        assertNull(drivingPermitClaim);
    }

    @Test
    void shouldNotSetDrivingPermitClaimWhenDrivingPermitVCIsMissing()
            throws HttpResponseExceptionWithErrorBody {
        List<UserIssuedCredentialsItem> userIssuedCredentialsItemList =
                List.of(
                        createUserIssuedCredentialsItem(
                                "user-id-1", "ukPassport", SIGNED_VC_1, Instant.now()),
                        createUserIssuedCredentialsItem(
                                "user-id-1", "fraud", SIGNED_VC_2, Instant.now()),
                        createUserIssuedCredentialsItem(
                                "user-id-1", "kbv", SIGNED_VC_3, Instant.now()),
                        createUserIssuedCredentialsItem(
                                "user-id-1", "address", SIGNED_VC_4, Instant.now()));

        List<VcStatusDto> currentVcStatuses =
                List.of(new VcStatusDto("test-issuer", true), new VcStatusDto("test-issuer", true));

        when(mockDataStore.getItems(anyString())).thenReturn(userIssuedCredentialsItemList);
        when(mockConfigurationService.getCredentialIssuer(anyString()))
                .thenReturn(
                        new CredentialIssuerConfig(
                                "test-cri",
                                "test cri",
                                URI.create("https://example.com/token"),
                                URI.create("https://example.com/credential"),
                                URI.create("https://example.com/authorize"),
                                "ipv-core",
                                "test-jwk",
                                "test-jwk",
                                "test-issuer",
                                URI.create("https://example.com/callback")));

        UserIdentity credentials =
                userIdentityService.generateUserIdentity(
                        "user-id-1", "test-sub", "P2", currentVcStatuses);

        JsonNode drivingPermitClaim = credentials.getDrivingPermitClaim();

        assertNull(drivingPermitClaim);
    }

    @Test
    void shouldNotSetDrivingPermitClaimWhenDrivingPermitVCFailed()
            throws HttpResponseExceptionWithErrorBody {
        List<UserIssuedCredentialsItem> userIssuedCredentialsItemList =
                List.of(
                        createUserIssuedCredentialsItem(
                                "user-id-1", "dcmaw", SIGNED_DCMAW_VC, Instant.now()),
                        createUserIssuedCredentialsItem(
                                "user-id-1", "ukPassport", SIGNED_VC_1, Instant.now()),
                        createUserIssuedCredentialsItem(
                                "user-id-1", "fraud", SIGNED_VC_2, Instant.now()),
                        createUserIssuedCredentialsItem(
                                "user-id-1", "address", SIGNED_VC_4, Instant.now()),
                        createUserIssuedCredentialsItem(
                                "user-id-1", "kbv", SIGNED_VC_3, Instant.now()));

        List<VcStatusDto> currentVcStatuses =
                List.of(
                        new VcStatusDto("test-issuer", true),
                        new VcStatusDto("dcmaw-issuer", false));

        when(mockDataStore.getItems(anyString())).thenReturn(userIssuedCredentialsItemList);
        when(mockConfigurationService.getCredentialIssuer("ukPassport"))
                .thenReturn(
                        new CredentialIssuerConfig(
                                "test-cri",
                                "test cri",
                                URI.create("https://example.com/token"),
                                URI.create("https://example.com/credential"),
                                URI.create("https://example.com/authorize"),
                                "ipv-core",
                                "test-jwk",
                                "test-jwk",
                                "test-issuer",
                                URI.create("https://example.com/callback")));
        when(mockConfigurationService.getCredentialIssuer("fraud"))
                .thenReturn(
                        new CredentialIssuerConfig(
                                "test-cri",
                                "test cri",
                                URI.create("https://example.com/token"),
                                URI.create("https://example.com/credential"),
                                URI.create("https://example.com/authorize"),
                                "ipv-core",
                                "test-jwk",
                                "test-jwk",
                                "test-issuer",
                                URI.create("https://example.com/callback")));
        when(mockConfigurationService.getCredentialIssuer("address"))
                .thenReturn(
                        new CredentialIssuerConfig(
                                "test-cri",
                                "test cri",
                                URI.create("https://example.com/token"),
                                URI.create("https://example.com/credential"),
                                URI.create("https://example.com/authorize"),
                                "ipv-core",
                                "test-jwk",
                                "test-jwk",
                                "test-issuer",
                                URI.create("https://example.com/callback")));
        when(mockConfigurationService.getCredentialIssuer("kbv"))
                .thenReturn(
                        new CredentialIssuerConfig(
                                "test-cri",
                                "test cri",
                                URI.create("https://example.com/token"),
                                URI.create("https://example.com/credential"),
                                URI.create("https://example.com/authorize"),
                                "ipv-core",
                                "test-jwk",
                                "test-jwk",
                                "test-issuer",
                                URI.create("https://example.com/callback")));
        when(mockConfigurationService.getCredentialIssuer("dcmaw"))
                .thenReturn(
                        new CredentialIssuerConfig(
                                "test-cri",
                                "test cri",
                                URI.create("https://example.com/token"),
                                URI.create("https://example.com/credential"),
                                URI.create("https://example.com/authorize"),
                                "ipv-core",
                                "test-jwk",
                                "test-jwk",
                                "dcmaw-issuer",
                                URI.create("https://example.com/callback")));

        UserIdentity credentials =
                userIdentityService.generateUserIdentity(
                        "user-id-1", "test-sub", "P2", currentVcStatuses);

        JsonNode drivingPermitClaim = credentials.getDrivingPermitClaim();

        assertNull(drivingPermitClaim);
    }

    @Test
    void shouldThrowExceptionWhenMissingDrivingPermitProperty() {
        List<UserIssuedCredentialsItem> userIssuedCredentialsItemList =
                List.of(
                        createUserIssuedCredentialsItem(
                                "user-id-1",
                                "dcmaw",
                                SIGNED_DCMAW_VC_MISSING_DRIVING_PERMIT_PROPERTY,
                                Instant.now()));

        List<VcStatusDto> currentVcStatuses = List.of(new VcStatusDto("dcmaw-issuer", true));

        when(mockDataStore.getItems(anyString())).thenReturn(userIssuedCredentialsItemList);
        when(mockConfigurationService.getCredentialIssuer(anyString()))
                .thenReturn(
                        new CredentialIssuerConfig(
                                "test-cri",
                                "test cri",
                                URI.create("https://example.com/token"),
                                URI.create("https://example.com/credential"),
                                URI.create("https://example.com/authorize"),
                                "ipv-core",
                                "test-jwk",
                                "test-jwk",
                                "dcmaw-issuer",
                                URI.create("https://example.com/callback")));

        HttpResponseExceptionWithErrorBody thrownError =
                assertThrows(
                        HttpResponseExceptionWithErrorBody.class,
                        () ->
                                userIdentityService.generateUserIdentity(
                                        "user-id-1", "test-sub", "P2", currentVcStatuses));

        assertEquals(500, thrownError.getResponseCode());
        assertEquals(
                ErrorResponse.FAILED_TO_GENERATE_DRIVING_PERMIT_CLAIM.getCode(),
                thrownError.getErrorBody().get("error"));
        assertEquals(
                ErrorResponse.FAILED_TO_GENERATE_DRIVING_PERMIT_CLAIM.getMessage(),
                thrownError.getErrorBody().get("error_description"));
    }

    @Test
    void generateUserIdentityShouldThrowIfDcmawVCCanNotBeParsed() {
        List<UserIssuedCredentialsItem> userIssuedCredentialsItemList =
                List.of(
                        createUserIssuedCredentialsItem(
                                "user-id-1", "ukPassport", SIGNED_VC_1, Instant.now()),
                        createUserIssuedCredentialsItem(
                                "user-id-1", "fraud", SIGNED_VC_2, Instant.now()),
                        createUserIssuedCredentialsItem(
                                "user-id-1", "kbv", SIGNED_VC_3, Instant.now()),
                        createUserIssuedCredentialsItem(
                                "user-id-1", "address", SIGNED_ADDRESS_VC, Instant.now()),
                        createUserIssuedCredentialsItem(
                                "user-id-1", "dcmaw", "GARBAGE", Instant.now()));

        List<VcStatusDto> currentVcStatuses = List.of(new VcStatusDto("dcmaw-issuer", true));

        when(mockDataStore.getItems(anyString())).thenReturn(userIssuedCredentialsItemList);
        when(mockConfigurationService.getCredentialIssuer(anyString()))
                .thenReturn(
                        new CredentialIssuerConfig(
                                "test-cri",
                                "test cri",
                                URI.create("https://example.com/token"),
                                URI.create("https://example.com/credential"),
                                URI.create("https://example.com/authorize"),
                                "ipv-core",
                                "test-jwk",
                                "test-jwk",
                                "dcmaw-issuer",
                                URI.create("https://example.com/callback")));

        HttpResponseExceptionWithErrorBody thrownException =
                assertThrows(
                        HttpResponseExceptionWithErrorBody.class,
                        () ->
                                userIdentityService.generateUserIdentity(
                                        "user-id-1", "test-sub", "P2", currentVcStatuses));

        assertEquals(500, thrownException.getResponseCode());
        assertEquals(
                ErrorResponse.FAILED_TO_GENERATE_DRIVING_PERMIT_CLAIM.getCode(),
                thrownException.getErrorBody().get("error"));
        assertEquals(
                ErrorResponse.FAILED_TO_GENERATE_DRIVING_PERMIT_CLAIM.getMessage(),
                thrownException.getErrorBody().get("error_description"));
    }

    private UserIssuedCredentialsItem createUserIssuedCredentialsItem(
            String userId, String credentialIssuer, String credential, Instant dateCreated) {
        UserIssuedCredentialsItem userIssuedCredentialsItem = new UserIssuedCredentialsItem();
        userIssuedCredentialsItem.setUserId(userId);
        userIssuedCredentialsItem.setCredentialIssuer(credentialIssuer);
        userIssuedCredentialsItem.setCredential(credential);
        userIssuedCredentialsItem.setDateCreated(dateCreated);
        userIssuedCredentialsItem.setExpirationTime(dateCreated.plusSeconds(1000L));
        return userIssuedCredentialsItem;
    }
}
