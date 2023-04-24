package uk.gov.di.ipv.core.library.service;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.crypto.ECDSASigner;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import uk.gov.di.ipv.core.library.domain.ErrorResponse;
import uk.gov.di.ipv.core.library.domain.IdentityClaim;
import uk.gov.di.ipv.core.library.domain.UserIdentity;
import uk.gov.di.ipv.core.library.domain.VectorOfTrust;
import uk.gov.di.ipv.core.library.dto.VcStatusDto;
import uk.gov.di.ipv.core.library.exceptions.HttpResponseExceptionWithErrorBody;
import uk.gov.di.ipv.core.library.persistence.DataStore;
import uk.gov.di.ipv.core.library.persistence.item.VcStoreItem;

import java.security.KeyFactory;
import java.security.NoSuchAlgorithmException;
import java.security.interfaces.ECPrivateKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.time.*;
import java.util.Base64;
import java.util.Collections;
import java.util.Date;
import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;
import static uk.gov.di.ipv.core.library.config.ConfigurationVariable.BACKEND_SESSION_TIMEOUT;
import static uk.gov.di.ipv.core.library.config.ConfigurationVariable.CORE_VTM_CLAIM;
import static uk.gov.di.ipv.core.library.config.ConfigurationVariable.VC_VALID_DURATION;
import static uk.gov.di.ipv.core.library.domain.UserIdentity.ADDRESS_CLAIM_NAME;
import static uk.gov.di.ipv.core.library.fixtures.TestFixtures.*;

@ExtendWith(MockitoExtension.class)
class UserIdentityServiceTest {
    private static final String USER_ID_1 = "user-id-1";
    private static final ObjectMapper objectMapper = new ObjectMapper();

    @Mock private ConfigService mockConfigService;

    @Mock private DataStore<VcStoreItem> mockDataStore;

    private UserIdentityService userIdentityService;

    @BeforeEach
    void setUp() {
        userIdentityService = new UserIdentityService(mockConfigService, mockDataStore);
    }

    @Test
    void shouldReturnCredentialsFromDataStore() throws HttpResponseExceptionWithErrorBody {
        List<VcStoreItem> vcStoreItems =
                List.of(
                        createVcStoreItem(USER_ID_1, "ukPassport", SIGNED_VC_1, Instant.now()),
                        createVcStoreItem(USER_ID_1, "fraud", SIGNED_VC_2, Instant.now()));

        List<VcStatusDto> currentVcStatuses =
                List.of(new VcStatusDto("test-issuer", true), new VcStatusDto("test-issuer", true));

        when(mockConfigService.getSsmParameter(CORE_VTM_CLAIM)).thenReturn("mock-vtm-claim");
        when(mockDataStore.getItems(anyString())).thenReturn(vcStoreItems);
        when(mockConfigService.getComponentId("ukPassport")).thenReturn("test-issuer");

        UserIdentity credentials =
                userIdentityService.generateUserIdentity(
                        USER_ID_1, "test-sub", "P2", currentVcStatuses);

        assertEquals(SIGNED_VC_1, credentials.getVcs().get(0));
        assertEquals(SIGNED_VC_2, credentials.getVcs().get(1));
        assertEquals("test-sub", credentials.getSub());
    }

    @Test
    void shouldReturnCredentialFromDataStoreForSpecificCri() {
        String ipvSessionId = "ipvSessionId";
        String criId = "criId";
        VcStoreItem credentialItem =
                createVcStoreItem(USER_ID_1, "ukPassport", SIGNED_VC_1, Instant.now());

        when(mockDataStore.getItem(ipvSessionId, criId)).thenReturn(credentialItem);

        VcStoreItem retrievedCredentialItem =
                userIdentityService.getVcStoreItem(ipvSessionId, criId);

        assertEquals(credentialItem, retrievedCredentialItem);
    }

    @Test
    void shouldSetVotClaimToP2OnSuccessfulIdentityCheck()
            throws HttpResponseExceptionWithErrorBody {
        List<VcStoreItem> vcStoreItems =
                List.of(
                        createVcStoreItem(USER_ID_1, "ukPassport", SIGNED_VC_1, Instant.now()),
                        createVcStoreItem(USER_ID_1, "fraud", SIGNED_VC_2, Instant.now()),
                        createVcStoreItem(USER_ID_1, "kbv", SIGNED_VC_3, Instant.now()),
                        createVcStoreItem(USER_ID_1, "address", SIGNED_VC_4, Instant.now()));

        List<VcStatusDto> currentVcStatuses =
                List.of(new VcStatusDto("test-issuer", true), new VcStatusDto("test-issuer", true));

        when(mockConfigService.getSsmParameter(CORE_VTM_CLAIM)).thenReturn("mock-vtm-claim");
        when(mockDataStore.getItems(anyString())).thenReturn(vcStoreItems);
        when(mockConfigService.getComponentId("ukPassport")).thenReturn("test-issuer");

        UserIdentity credentials =
                userIdentityService.generateUserIdentity(
                        USER_ID_1, "test-sub", "P2", currentVcStatuses);

        assertEquals(VectorOfTrust.P2.toString(), credentials.getVot());
    }

    @Test
    void checkBirthDateCorrelationInCredentialsReturnsTrueWhenBirthDatesSame()
            throws HttpResponseExceptionWithErrorBody {
        List<VcStoreItem> vcStoreItems =
                List.of(
                        createVcStoreItem(USER_ID_1, "ukPassport", SIGNED_VC_2, Instant.now()),
                        createVcStoreItem(USER_ID_1, "dcmaw", SIGNED_VC_3, Instant.now()));

        List<VcStatusDto> currentVcStatuses = List.of(new VcStatusDto("test-issuer", true));

        when(userIdentityService.getVcStoreItems(USER_ID_1)).thenReturn(vcStoreItems);
        when(mockConfigService.getComponentId(any())).thenReturn("test-issuer");

        boolean isValid =
                userIdentityService.checkBirthDateCorrelationInCredentials(
                        USER_ID_1, currentVcStatuses);

        assertTrue(isValid);
    }

    @Test
    void checkBirthDateCorrelationInCredentialsReturnsFalseWhenBirthDatesDiffer()
            throws HttpResponseExceptionWithErrorBody {
        List<VcStoreItem> vcStoreItems =
                List.of(
                        createVcStoreItem(USER_ID_1, "ukPassport", SIGNED_VC_1, Instant.now()),
                        createVcStoreItem(USER_ID_1, "dcmaw", SIGNED_VC_3, Instant.now()));

        List<VcStatusDto> currentVcStatuses = List.of(new VcStatusDto("test-issuer", true));

        when(userIdentityService.getVcStoreItems(USER_ID_1)).thenReturn(vcStoreItems);
        when(mockConfigService.getComponentId(any())).thenReturn("test-issuer");

        boolean isValid =
                userIdentityService.checkBirthDateCorrelationInCredentials(
                        USER_ID_1, currentVcStatuses);

        assertFalse(isValid);
    }

    @Test
    void shouldSetIdentityClaimWhenVotIsP2() throws HttpResponseExceptionWithErrorBody, Exception {
        List<VcStoreItem> vcStoreItems =
                List.of(
                        createVcStoreItem(USER_ID_1, "ukPassport", SIGNED_VC_1, Instant.now()),
                        createVcStoreItem(USER_ID_1, "fraud", SIGNED_VC_2, Instant.now()),
                        createVcStoreItem(USER_ID_1, "kbv", SIGNED_VC_3, Instant.now()),
                        createVcStoreItem(USER_ID_1, "address", SIGNED_VC_4, Instant.now()));

        List<VcStatusDto> currentVcStatuses =
                List.of(new VcStatusDto("test-issuer", true), new VcStatusDto("test-issuer", true));

        when(mockConfigService.getSsmParameter(CORE_VTM_CLAIM)).thenReturn("mock-vtm-claim");
        when(mockDataStore.getItems(anyString())).thenReturn(vcStoreItems);
        when(mockConfigService.getComponentId("ukPassport")).thenReturn("test-issuer");

        UserIdentity credentials =
                userIdentityService.generateUserIdentity(
                        USER_ID_1, "test-sub", "P2", currentVcStatuses);

        IdentityClaim identityClaim = credentials.getIdentityClaim();

        assertEquals("GivenName", identityClaim.getName().get(0).getNameParts().get(0).getType());
        assertEquals("Paul", identityClaim.getName().get(0).getNameParts().get(0).getValue());

        assertEquals("2020-02-03", identityClaim.getBirthDate().get(0).getValue());
    }

    @Test
    void shouldNotSetIdentityClaimWhenVotIsP0() throws HttpResponseExceptionWithErrorBody {
        List<VcStoreItem> vcStoreItems =
                List.of(
                        createVcStoreItem(USER_ID_1, "ukPassport", SIGNED_VC_1, Instant.now()),
                        createVcStoreItem(USER_ID_1, "fraud", SIGNED_VC_2, Instant.now()));

        List<VcStatusDto> currentVcStatuses =
                List.of(new VcStatusDto("test-issuer", true), new VcStatusDto("test-issuer", true));

        when(mockDataStore.getItems(anyString())).thenReturn(vcStoreItems);

        UserIdentity credentials =
                userIdentityService.generateUserIdentity(
                        USER_ID_1, "test-sub", "P0", currentVcStatuses);

        assertNull(credentials.getIdentityClaim());
    }

    @Test
    void shouldThrowExceptionWhenMissingNameProperty() {
        List<VcStoreItem> vcStoreItems =
                List.of(
                        createVcStoreItem(
                                USER_ID_1,
                                "ukPassport",
                                SIGNED_PASSPORT_VC_MISSING_NAME,
                                Instant.now()),
                        createVcStoreItem(USER_ID_1, "fraud", SIGNED_VC_2, Instant.now()),
                        createVcStoreItem(USER_ID_1, "kbv", SIGNED_VC_3, Instant.now()));

        List<VcStatusDto> currentVcStatuses =
                List.of(new VcStatusDto("test-issuer", true), new VcStatusDto("test-issuer", true));

        when(mockConfigService.getSsmParameter(CORE_VTM_CLAIM)).thenReturn("mock-vtm-claim");
        when(mockDataStore.getItems(anyString())).thenReturn(vcStoreItems);
        when(mockConfigService.getComponentId("ukPassport")).thenReturn("test-issuer");

        HttpResponseExceptionWithErrorBody thrownError =
                assertThrows(
                        HttpResponseExceptionWithErrorBody.class,
                        () ->
                                userIdentityService.generateUserIdentity(
                                        USER_ID_1, "test-sub", "P2", currentVcStatuses));

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
                                SIGNED_PASSPORT_VC_MISSING_BIRTH_DATE,
                                Instant.now()),
                        createVcStoreItem(USER_ID_1, "fraud", SIGNED_VC_2, Instant.now()),
                        createVcStoreItem(USER_ID_1, "kbv", SIGNED_VC_3, Instant.now()));

        List<VcStatusDto> currentVcStatuses =
                List.of(new VcStatusDto("test-issuer", true), new VcStatusDto("test-issuer", true));

        when(mockConfigService.getSsmParameter(CORE_VTM_CLAIM)).thenReturn("mock-vtm-claim");
        when(mockDataStore.getItems(anyString())).thenReturn(vcStoreItems);
        when(mockConfigService.getComponentId("ukPassport")).thenReturn("test-issuer");

        HttpResponseExceptionWithErrorBody thrownError =
                assertThrows(
                        HttpResponseExceptionWithErrorBody.class,
                        () ->
                                userIdentityService.generateUserIdentity(
                                        USER_ID_1, "test-sub", "P2", currentVcStatuses));

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
        when(mockConfigService.getSsmParameter(CORE_VTM_CLAIM)).thenReturn("mock-vtm-claim");

        List<VcStoreItem> vcStoreItems =
                List.of(
                        createVcStoreItem(USER_ID_1, "ukPassport", SIGNED_VC_1, Instant.now()),
                        createVcStoreItem(USER_ID_1, "fraud", SIGNED_VC_2, Instant.now()),
                        createVcStoreItem(USER_ID_1, "kbv", SIGNED_VC_3, Instant.now()),
                        createVcStoreItem(USER_ID_1, "address", SIGNED_VC_4, Instant.now()));

        List<VcStatusDto> currentVcStatuses =
                List.of(new VcStatusDto("test-issuer", true), new VcStatusDto("test-issuer", true));

        when(mockDataStore.getItems(anyString())).thenReturn(vcStoreItems);
        when(mockConfigService.getComponentId("ukPassport")).thenReturn("test-issuer");

        UserIdentity credentials =
                userIdentityService.generateUserIdentity(
                        USER_ID_1, "test-sub", "P2", currentVcStatuses);

        JsonNode passportClaim = credentials.getPassportClaim();

        assertEquals("123456789", passportClaim.get(0).get("documentNumber").asText());
        assertEquals("2020-01-01", passportClaim.get(0).get("expiryDate").asText());
    }

    @Test
    void shouldNotSetPassportClaimWhenVotIsP0() throws HttpResponseExceptionWithErrorBody {
        List<VcStoreItem> vcStoreItems =
                List.of(
                        createVcStoreItem(USER_ID_1, "ukPassport", SIGNED_VC_1, Instant.now()),
                        createVcStoreItem(USER_ID_1, "fraud", SIGNED_VC_2, Instant.now()));

        List<VcStatusDto> currentVcStatuses =
                List.of(new VcStatusDto("test-issuer", true), new VcStatusDto("test-issuer", true));

        when(mockDataStore.getItems(anyString())).thenReturn(vcStoreItems);

        UserIdentity credentials =
                userIdentityService.generateUserIdentity(
                        USER_ID_1, "test-sub", "P0", currentVcStatuses);

        assertNull(credentials.getPassportClaim());
    }

    @Test
    void shouldReturnEmptyWhenMissingPassportProperty() throws HttpResponseExceptionWithErrorBody {
        List<VcStoreItem> vcStoreItems =
                List.of(
                        createVcStoreItem(
                                USER_ID_1,
                                "ukPassport",
                                SIGNED_PASSPORT_VC_MISSING_PASSPORT,
                                Instant.now()),
                        createVcStoreItem(USER_ID_1, "fraud", SIGNED_VC_2, Instant.now()),
                        createVcStoreItem(USER_ID_1, "kbv", SIGNED_VC_3, Instant.now()),
                        createVcStoreItem(USER_ID_1, "address", SIGNED_VC_4, Instant.now()));

        List<VcStatusDto> currentVcStatuses =
                List.of(new VcStatusDto("test-issuer", true), new VcStatusDto("test-issuer", true));

        when(mockConfigService.getSsmParameter(CORE_VTM_CLAIM)).thenReturn("mock-vtm-claim");
        when(mockDataStore.getItems(anyString())).thenReturn(vcStoreItems);
        when(mockConfigService.getComponentId("ukPassport")).thenReturn("test-issuer");

        UserIdentity credentials =
                userIdentityService.generateUserIdentity(
                        USER_ID_1, "test-sub", "P2", currentVcStatuses);

        assertNull(credentials.getPassportClaim());
    }

    @Test
    void shouldSetSubClaimOnUserIdentity() throws HttpResponseExceptionWithErrorBody {
        when(mockConfigService.getSsmParameter(CORE_VTM_CLAIM)).thenReturn("mock-vtm-claim");

        List<VcStatusDto> currentVcStatuses =
                List.of(new VcStatusDto("test-issuer", true), new VcStatusDto("test-issuer", true));

        UserIdentity credentials =
                userIdentityService.generateUserIdentity(
                        USER_ID_1, "test-sub", "P2", currentVcStatuses);

        assertEquals("test-sub", credentials.getSub());
    }

    @Test
    void shouldSetVtmClaimOnUserIdentity() throws HttpResponseExceptionWithErrorBody {
        when(mockConfigService.getSsmParameter(CORE_VTM_CLAIM)).thenReturn("mock-vtm-claim");

        List<VcStatusDto> currentVcStatuses =
                List.of(new VcStatusDto("test-issuer", true), new VcStatusDto("test-issuer", true));

        UserIdentity credentials =
                userIdentityService.generateUserIdentity(
                        USER_ID_1, "test-sub", "P2", currentVcStatuses);

        assertEquals("mock-vtm-claim", credentials.getVtm());
    }

    @Test
    void generateUserIdentityShouldSetAddressClaimOnUserIdentity() throws Exception {
        List<VcStoreItem> vcStoreItems =
                List.of(
                        createVcStoreItem(USER_ID_1, "ukPassport", SIGNED_VC_1, Instant.now()),
                        createVcStoreItem(USER_ID_1, "fraud", SIGNED_VC_2, Instant.now()),
                        createVcStoreItem(USER_ID_1, "kbv", SIGNED_VC_3, Instant.now()),
                        createVcStoreItem(USER_ID_1, "address", SIGNED_ADDRESS_VC, Instant.now()));

        List<VcStatusDto> currentVcStatuses =
                List.of(new VcStatusDto("test-issuer", true), new VcStatusDto("test-issuer", true));

        when(mockConfigService.getSsmParameter(CORE_VTM_CLAIM)).thenReturn("mock-vtm-claim");
        when(mockDataStore.getItems(anyString())).thenReturn(vcStoreItems);
        when(mockConfigService.getComponentId("ukPassport")).thenReturn("test-issuer");

        UserIdentity userIdentity =
                userIdentityService.generateUserIdentity(
                        USER_ID_1, "test-sub", "P2", currentVcStatuses);

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
        List<VcStoreItem> vcStoreItems =
                List.of(
                        createVcStoreItem(USER_ID_1, "ukPassport", SIGNED_VC_1, Instant.now()),
                        createVcStoreItem(USER_ID_1, "fraud", SIGNED_VC_2, Instant.now()),
                        createVcStoreItem(USER_ID_1, "kbv", SIGNED_VC_3, Instant.now()),
                        createVcStoreItem(
                                USER_ID_1,
                                "address",
                                SIGNED_ADDRESS_VC_MISSING_ADDRESS_PROPERTY,
                                Instant.now()));

        List<VcStatusDto> currentVcStatuses =
                List.of(new VcStatusDto("test-issuer", true), new VcStatusDto("test-issuer", true));

        when(mockConfigService.getSsmParameter(CORE_VTM_CLAIM)).thenReturn("mock-vtm-claim");
        when(mockDataStore.getItems(anyString())).thenReturn(vcStoreItems);
        when(mockConfigService.getComponentId("ukPassport")).thenReturn("test-issuer");

        HttpResponseExceptionWithErrorBody thrownException =
                assertThrows(
                        HttpResponseExceptionWithErrorBody.class,
                        () ->
                                userIdentityService.generateUserIdentity(
                                        USER_ID_1, "test-sub", "P2", currentVcStatuses));

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
                        createVcStoreItem(USER_ID_1, "ukPassport", SIGNED_VC_1, Instant.now()),
                        createVcStoreItem(USER_ID_1, "fraud", SIGNED_VC_2, Instant.now()),
                        createVcStoreItem(USER_ID_1, "kbv", SIGNED_VC_3, Instant.now()),
                        createVcStoreItem(USER_ID_1, "address", "GARBAGE", Instant.now()));

        List<VcStatusDto> currentVcStatuses =
                List.of(new VcStatusDto("test-issuer", true), new VcStatusDto("test-issuer", true));

        when(mockConfigService.getSsmParameter(CORE_VTM_CLAIM)).thenReturn("mock-vtm-claim");
        when(mockDataStore.getItems(anyString())).thenReturn(vcStoreItems);
        when(mockConfigService.getComponentId("ukPassport")).thenReturn("test-issuer");

        HttpResponseExceptionWithErrorBody thrownException =
                assertThrows(
                        HttpResponseExceptionWithErrorBody.class,
                        () ->
                                userIdentityService.generateUserIdentity(
                                        USER_ID_1, "test-sub", "P2", currentVcStatuses));

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
        List<VcStoreItem> vcStoreItems =
                List.of(
                        createVcStoreItem(USER_ID_1, "fraud", SIGNED_VC_2, Instant.now()),
                        createVcStoreItem(USER_ID_1, "kbv", SIGNED_VC_3, Instant.now()),
                        createVcStoreItem(USER_ID_1, "address", SIGNED_ADDRESS_VC, Instant.now()));

        List<VcStatusDto> currentVcStatuses =
                List.of(new VcStatusDto("test-issuer", true), new VcStatusDto("test-issuer", true));

        when(mockDataStore.getItems(anyString())).thenReturn(vcStoreItems);

        UserIdentity credentials =
                userIdentityService.generateUserIdentity(
                        USER_ID_1, "test-sub", "P0", currentVcStatuses);

        assertNull(credentials.getAddressClaim());
    }

    @Test
    void shouldReturnListOfVcsForSharedAttributes() {
        List<VcStoreItem> vcStoreItems =
                List.of(
                        createVcStoreItem(USER_ID_1, "ukPassport", SIGNED_VC_1, Instant.now()),
                        createVcStoreItem(USER_ID_1, "fraud", SIGNED_VC_2, Instant.now()));

        when(mockDataStore.getItems(anyString())).thenReturn(vcStoreItems);

        List<String> vcList = userIdentityService.getUserIssuedCredentials(USER_ID_1);

        assertEquals(SIGNED_VC_1, vcList.get(0));
        assertEquals(SIGNED_VC_2, vcList.get(1));
    }

    @Test
    void shouldDeleteExistingVCsIfAnyDueToExpireWithinSessionTimeout() {
        when(mockConfigService.getSsmParameter(BACKEND_SESSION_TIMEOUT)).thenReturn("7200");

        List<VcStoreItem> vcStoreItems =
                List.of(
                        createVcStoreItem("a-users-id", "ukPassport", SIGNED_VC_1, Instant.now()),
                        createVcStoreItem("a-users-id", "fraud", SIGNED_VC_2, Instant.now()),
                        createVcStoreItem("a-users-id", "sausages", SIGNED_VC_3, Instant.now()));
        when(mockDataStore.getItems("a-users-id")).thenReturn(vcStoreItems);

        List<VcStoreItem> expiredVcStoreItems =
                List.of(createVcStoreItem("a-users-id", "fraud", SIGNED_VC_2, Instant.now()));
        when(mockDataStore.getItemsWithAttributeLessThanOrEqualValue(
                        eq("a-users-id"), eq("expirationTime"), anyString()))
                .thenReturn(expiredVcStoreItems);

        userIdentityService.deleteVcStoreItemsIfAnyExpired("a-users-id");

        verify(mockDataStore).delete("a-users-id", "ukPassport");
        verify(mockDataStore).delete("a-users-id", "fraud");
        verify(mockDataStore).delete("a-users-id", "sausages");
    }

    @Test
    void shouldNotDeleteExistingVCsIfNoneAreDueToExpireWithinSessionTimeout() {
        when(mockConfigService.getSsmParameter(BACKEND_SESSION_TIMEOUT)).thenReturn("7200");

        List<VcStoreItem> expiredVcStoreItems = Collections.emptyList();
        when(mockDataStore.getItemsWithAttributeLessThanOrEqualValue(
                        eq("a-users-id"), eq("expirationTime"), anyString()))
                .thenReturn(expiredVcStoreItems);

        userIdentityService.deleteVcStoreItemsIfAnyExpired("a-users-id");

        verify(mockDataStore, times(0)).delete(anyString(), anyString());
    }

    @Test
    void shouldDeleteExistingVCsIfAnyInvalidWithinSessionTimeout() {
        when(mockConfigService.getSsmParameter(BACKEND_SESSION_TIMEOUT)).thenReturn("7200");
        when(mockConfigService.getSsmParameter(VC_VALID_DURATION)).thenReturn("P182DT12H");

        List<VcStoreItem> vcStoreItems =
                List.of(
                        createVcStoreItem("a-users-id", "ukPassport", SIGNED_VC_1, Instant.now()),
                        createVcStoreItem("a-users-id", "fraud", SIGNED_VC_2, Instant.now()),
                        createVcStoreItem("a-users-id", "sausages", SIGNED_VC_3, Instant.now()));
        when(mockDataStore.getItems("a-users-id")).thenReturn(vcStoreItems);

        userIdentityService.deleteVcStoreItemsIfAnyInvalid("a-users-id");

        verify(mockDataStore).delete("a-users-id", "ukPassport");
        verify(mockDataStore).delete("a-users-id", "fraud");
        verify(mockDataStore).delete("a-users-id", "sausages");
    }

    @Test
    void shouldNotDeleteExistingVCsIfAllValidWithinSessionTimeout() throws Exception {
        when(mockConfigService.getSsmParameter(BACKEND_SESSION_TIMEOUT)).thenReturn("7200");
        when(mockConfigService.getSsmParameter(VC_VALID_DURATION)).thenReturn("P182DT12H");
        Date nbf = Date.from(ZonedDateTime.now().plusYears(1).toInstant());

        SignedJWT signedJwt =
                new SignedJWT(
                        new JWSHeader.Builder(JWSAlgorithm.ES256).build(),
                        new JWTClaimsSet.Builder()
                                .subject("testSubject")
                                .issuer("ukPassport")
                                .notBeforeTime(nbf)
                                .build());
        signedJwt.sign(new ECDSASigner(getPrivateKey()));
        String signedVc = signedJwt.serialize();

        List<VcStoreItem> vcStoreItems =
                List.of(createVcStoreItem("a-users-id", "ukPassport", signedVc, Instant.now()));
        when(mockDataStore.getItems("a-users-id")).thenReturn(vcStoreItems);

        userIdentityService.deleteVcStoreItemsIfAnyInvalid("a-users-id");

        verify(mockDataStore, times(0)).delete(anyString(), anyString());
    }

    @Test
    void shouldDeleteAllExistingVCs() {
        List<VcStoreItem> vcStoreItems =
                List.of(
                        createVcStoreItem("a-users-id", "ukPassport", SIGNED_VC_1, Instant.now()),
                        createVcStoreItem("a-users-id", "fraud", SIGNED_VC_2, Instant.now()),
                        createVcStoreItem("a-users-id", "sausages", SIGNED_VC_3, Instant.now()));

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
                                USER_ID_1, testCredentialIssuer, SIGNED_VC_1, Instant.now()));

        when(mockDataStore.getItems(userId)).thenReturn(credentialItem);

        var vcStoreItems = userIdentityService.getVcStoreItems(userId);

        assertTrue(
                vcStoreItems.stream()
                        .map(VcStoreItem::getCredentialIssuer)
                        .anyMatch(item -> testCredentialIssuer.equals(item)));
    }

    @Test
    void shouldSetDrivingPermitClaimWhenVotIsP2() throws HttpResponseExceptionWithErrorBody {
        List<VcStoreItem> vcStoreItems =
                List.of(
                        createVcStoreItem(USER_ID_1, "dcmaw", SIGNED_DCMAW_VC, Instant.now()),
                        createVcStoreItem(USER_ID_1, "fraud", SIGNED_VC_2, Instant.now()),
                        createVcStoreItem(USER_ID_1, "address", SIGNED_VC_4, Instant.now()));

        List<VcStatusDto> currentVcStatuses =
                List.of(
                        new VcStatusDto("test-issuer", true),
                        new VcStatusDto("dcmaw-issuer", true));

        when(mockConfigService.getSsmParameter(CORE_VTM_CLAIM)).thenReturn("mock-vtm-claim");
        when(mockDataStore.getItems(anyString())).thenReturn(vcStoreItems);
        when(mockConfigService.getComponentId("dcmaw")).thenReturn("test-issuer");

        UserIdentity credentials =
                userIdentityService.generateUserIdentity(
                        USER_ID_1, "test-sub", "P2", currentVcStatuses);

        JsonNode drivingPermitClaim = credentials.getDrivingPermitClaim();

        assertEquals("MORGA753116SM9IJ", drivingPermitClaim.get(0).get("personalNumber").asText());
        assertEquals("123456", drivingPermitClaim.get(0).get("issueNumber").asText());
        assertEquals("2023-01-18", drivingPermitClaim.get(0).get("expiryDate").asText());
    }

    @Test
    void shouldNotSetDrivingPermitClaimWhenVotIsP0() throws HttpResponseExceptionWithErrorBody {
        List<VcStoreItem> vcStoreItems =
                List.of(
                        createVcStoreItem(USER_ID_1, "dcmaw", SIGNED_DCMAW_VC, Instant.now()),
                        createVcStoreItem(USER_ID_1, "fraud", SIGNED_VC_2, Instant.now()),
                        createVcStoreItem(USER_ID_1, "address", SIGNED_VC_4, Instant.now()));

        List<VcStatusDto> currentVcStatuses =
                List.of(
                        new VcStatusDto("test-issuer", true),
                        new VcStatusDto("dcmaw-issuer", true));

        when(mockDataStore.getItems(anyString())).thenReturn(vcStoreItems);

        UserIdentity credentials =
                userIdentityService.generateUserIdentity(
                        USER_ID_1, "test-sub", "P0", currentVcStatuses);

        JsonNode drivingPermitClaim = credentials.getDrivingPermitClaim();

        assertNull(drivingPermitClaim);
    }

    @Test
    void shouldNotSetDrivingPermitClaimWhenDrivingPermitVCIsMissing()
            throws HttpResponseExceptionWithErrorBody {
        List<VcStoreItem> vcStoreItems =
                List.of(
                        createVcStoreItem(USER_ID_1, "ukPassport", SIGNED_VC_1, Instant.now()),
                        createVcStoreItem(USER_ID_1, "fraud", SIGNED_VC_2, Instant.now()),
                        createVcStoreItem(USER_ID_1, "kbv", SIGNED_VC_3, Instant.now()),
                        createVcStoreItem(USER_ID_1, "address", SIGNED_VC_4, Instant.now()));

        List<VcStatusDto> currentVcStatuses =
                List.of(new VcStatusDto("test-issuer", true), new VcStatusDto("test-issuer", true));

        when(mockConfigService.getSsmParameter(CORE_VTM_CLAIM)).thenReturn("mock-vtm-claim");
        when(mockDataStore.getItems(anyString())).thenReturn(vcStoreItems);
        when(mockConfigService.getComponentId("ukPassport")).thenReturn("test-issuer");

        UserIdentity credentials =
                userIdentityService.generateUserIdentity(
                        USER_ID_1, "test-sub", "P2", currentVcStatuses);

        JsonNode drivingPermitClaim = credentials.getDrivingPermitClaim();

        assertNull(drivingPermitClaim);
    }

    @Test
    void shouldNotSetDrivingPermitClaimWhenDrivingPermitVCFailed()
            throws HttpResponseExceptionWithErrorBody {
        List<VcStoreItem> vcStoreItems =
                List.of(
                        createVcStoreItem(USER_ID_1, "dcmaw", SIGNED_DCMAW_VC, Instant.now()),
                        createVcStoreItem(USER_ID_1, "ukPassport", SIGNED_VC_1, Instant.now()),
                        createVcStoreItem(USER_ID_1, "fraud", SIGNED_VC_2, Instant.now()),
                        createVcStoreItem(USER_ID_1, "address", SIGNED_VC_4, Instant.now()),
                        createVcStoreItem(USER_ID_1, "kbv", SIGNED_VC_3, Instant.now()));

        List<VcStatusDto> currentVcStatuses =
                List.of(
                        new VcStatusDto("test-issuer", true),
                        new VcStatusDto("dcmaw-issuer", false));

        when(mockConfigService.getSsmParameter(CORE_VTM_CLAIM)).thenReturn("mock-vtm-claim");
        when(mockDataStore.getItems(anyString())).thenReturn(vcStoreItems);
        when(mockConfigService.getComponentId("dcmaw")).thenReturn("dcmaw-issuer");
        when(mockConfigService.getComponentId("ukPassport")).thenReturn("test-issuer");
        when(mockConfigService.getComponentId("fraud")).thenReturn("test-issuer");
        when(mockConfigService.getComponentId("address")).thenReturn("test-issuer");
        when(mockConfigService.getComponentId("kbv")).thenReturn("test-issuer");

        UserIdentity credentials =
                userIdentityService.generateUserIdentity(
                        USER_ID_1, "test-sub", "P2", currentVcStatuses);

        JsonNode drivingPermitClaim = credentials.getDrivingPermitClaim();

        assertNull(drivingPermitClaim);
    }

    @Test
    void shouldReturnEmptyWhenMissingDrivingPermitProperty()
            throws HttpResponseExceptionWithErrorBody {
        List<VcStoreItem> vcStoreItems =
                List.of(
                        createVcStoreItem(
                                USER_ID_1,
                                "dcmaw",
                                SIGNED_DCMAW_VC_MISSING_DRIVING_PERMIT_PROPERTY,
                                Instant.now()));

        List<VcStatusDto> currentVcStatuses = List.of(new VcStatusDto("dcmaw-issuer", true));

        when(mockConfigService.getSsmParameter(CORE_VTM_CLAIM)).thenReturn("mock-vtm-claim");
        when(mockDataStore.getItems(anyString())).thenReturn(vcStoreItems);
        when(mockConfigService.getComponentId("dcmaw")).thenReturn("dcmaw-issuer");

        UserIdentity credentials =
                userIdentityService.generateUserIdentity(
                        USER_ID_1, "test-sub", "P2", currentVcStatuses);

        assertNull(credentials.getDrivingPermitClaim());
    }

    @Test
    void generateUserIdentityShouldThrowIfDcmawVCCanNotBeParsed() {
        List<VcStoreItem> vcStoreItems =
                List.of(
                        createVcStoreItem(USER_ID_1, "ukPassport", SIGNED_VC_1, Instant.now()),
                        createVcStoreItem(USER_ID_1, "fraud", SIGNED_VC_2, Instant.now()),
                        createVcStoreItem(USER_ID_1, "kbv", SIGNED_VC_3, Instant.now()),
                        createVcStoreItem(USER_ID_1, "address", SIGNED_ADDRESS_VC, Instant.now()),
                        createVcStoreItem(USER_ID_1, "dcmaw", "GARBAGE", Instant.now()));

        List<VcStatusDto> currentVcStatuses = List.of(new VcStatusDto("dcmaw-issuer", true));

        when(mockConfigService.getSsmParameter(CORE_VTM_CLAIM)).thenReturn("mock-vtm-claim");
        when(mockDataStore.getItems(anyString())).thenReturn(vcStoreItems);
        when(mockConfigService.getComponentId(anyString())).thenReturn("dcmaw-issuer");

        HttpResponseExceptionWithErrorBody thrownException =
                assertThrows(
                        HttpResponseExceptionWithErrorBody.class,
                        () ->
                                userIdentityService.generateUserIdentity(
                                        USER_ID_1, "test-sub", "P2", currentVcStatuses));

        assertEquals(500, thrownException.getResponseCode());
        assertEquals(
                ErrorResponse.FAILED_TO_GENERATE_DRIVING_PERMIT_CLAIM.getCode(),
                thrownException.getErrorBody().get("error"));
        assertEquals(
                ErrorResponse.FAILED_TO_GENERATE_DRIVING_PERMIT_CLAIM.getMessage(),
                thrownException.getErrorBody().get("error_description"));
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

    private ECPrivateKey getPrivateKey() throws InvalidKeySpecException, NoSuchAlgorithmException {
        return (ECPrivateKey)
                KeyFactory.getInstance("EC")
                        .generatePrivate(
                                new PKCS8EncodedKeySpec(
                                        Base64.getDecoder().decode(EC_PRIVATE_KEY)));
    }
}
