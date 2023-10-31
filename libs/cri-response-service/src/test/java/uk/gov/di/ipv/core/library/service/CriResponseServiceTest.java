package uk.gov.di.ipv.core.library.service;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.ArgumentCaptor;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import uk.gov.di.ipv.core.library.persistence.DataStore;
import uk.gov.di.ipv.core.library.persistence.item.CriResponseItem;

import java.time.Instant;
import java.util.List;
import java.util.Objects;
import java.util.UUID;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;
import static uk.gov.di.ipv.core.library.domain.CriConstants.F2F_CRI;
import static uk.gov.di.ipv.core.library.fixtures.TestFixtures.VC_PASSPORT_NON_DCMAW_SUCCESSFUL;

@ExtendWith(MockitoExtension.class)
public class CriResponseServiceTest {
    @Mock private ConfigService mockConfigService;

    @Mock private DataStore<CriResponseItem> mockDataStore;

    private CriResponseService criResponseService;

    private static final String USER_ID_1 = "user-id-1";
    private static final String USER_ID = "userId";
    private static final String TEST_USER_ID = UUID.randomUUID().toString();
    private static final String TEST_CREDENTIAL_ISSUER = F2F_CRI;
    private static final String TEST_ISSUER_RESPONSE =
            "{\"sub\":"
                    + TEST_USER_ID
                    + "\","
                    + "\"https://vocab.account.gov.uk/v1/credentialStatus\":\"pending\"}";

    private static final String TEST_OAUTH_STATE = UUID.randomUUID().toString();

    @BeforeEach
    void setUp() {
        criResponseService = new CriResponseService(mockConfigService, mockDataStore);
    }

    @Test
    void shouldReturnCredentialFromDataStoreForSpecificCri() {
        String ipvSessionId = "ipvSessionId";
        String criId = "criId";
        CriResponseItem criResponseItem =
                createCriResponseStoreItem(
                        USER_ID_1, "ukPassport", VC_PASSPORT_NON_DCMAW_SUCCESSFUL, Instant.now());

        when(mockDataStore.getItem(ipvSessionId, criId)).thenReturn(criResponseItem);

        CriResponseItem retrievedCredentialItem =
                criResponseService.getCriResponseItem(ipvSessionId, criId);

        assertEquals(criResponseItem, retrievedCredentialItem);
    }

    @Test
    void shouldReturnCredentialIssuersFromDataStoreForSpecificUserId() {

        List<CriResponseItem> criResponseItem =
                List.of(
                        createCriResponseStoreItem(
                                USER_ID_1,
                                TEST_CREDENTIAL_ISSUER,
                                VC_PASSPORT_NON_DCMAW_SUCCESSFUL,
                                Instant.now()));

        when(mockDataStore.getItems(USER_ID)).thenReturn(criResponseItem);

        var criResponseItems = criResponseService.getCriResponseItems(USER_ID);

        assertTrue(
                criResponseItems.stream()
                        .map(CriResponseItem::getCredentialIssuer)
                        .anyMatch(item -> TEST_CREDENTIAL_ISSUER.equals(item)));
    }

    @Test
    void shouldPersistCriResponse() {
        final Instant testCreatedDate = Instant.now();
        final CriResponseItem testCriResponseItem =
                createCriResponseStoreItem(
                        TEST_USER_ID,
                        TEST_CREDENTIAL_ISSUER,
                        TEST_ISSUER_RESPONSE,
                        testCreatedDate);

        criResponseService.persistCriResponse(
                TEST_USER_ID,
                TEST_CREDENTIAL_ISSUER,
                TEST_ISSUER_RESPONSE,
                TEST_OAUTH_STATE,
                CriResponseService.STATUS_PENDING);

        ArgumentCaptor<CriResponseItem> persistedCriResponseItemCaptor =
                ArgumentCaptor.forClass(CriResponseItem.class);
        verify(mockDataStore, times(1)).create(persistedCriResponseItemCaptor.capture(), any());
        assertEquals(1, persistedCriResponseItemCaptor.getAllValues().size());
        final CriResponseItem persistedCriResponseItem =
                persistedCriResponseItemCaptor.getAllValues().get(0);
        assertEquals(TEST_USER_ID, persistedCriResponseItem.getUserId());
        assertEquals(TEST_CREDENTIAL_ISSUER, persistedCriResponseItem.getCredentialIssuer());
        assertEquals(TEST_ISSUER_RESPONSE, persistedCriResponseItem.getIssuerResponse());
        assertEquals(TEST_OAUTH_STATE, persistedCriResponseItem.getOauthState());
    }

    @Test
    void shouldReturnTrueWhenUserHasFaceToFaceRequest() {
        CriResponseItem criResponseItem =
                createCriResponseStoreItem(
                        USER_ID_1, F2F_CRI, VC_PASSPORT_NON_DCMAW_SUCCESSFUL, Instant.now());

        when(mockDataStore.getItem(USER_ID_1, F2F_CRI)).thenReturn(criResponseItem);

        CriResponseItem retrievedCredentialItem =
                criResponseService.getFaceToFaceRequest(USER_ID_1);

        assertTrue(!Objects.isNull(retrievedCredentialItem));
    }

    @Test
    void shouldDeleteExistingWhenUserHasDeleteRequest() {
        CriResponseItem criResponseItem =
                createCriResponseStoreItem(
                        USER_ID_1,
                        TEST_CREDENTIAL_ISSUER,
                        VC_PASSPORT_NON_DCMAW_SUCCESSFUL,
                        Instant.now());

        when(mockDataStore.delete(USER_ID_1, TEST_CREDENTIAL_ISSUER)).thenReturn(criResponseItem);

        criResponseService.deleteCriResponseItem(USER_ID_1, TEST_CREDENTIAL_ISSUER);

        verify(mockDataStore, times(1)).delete(USER_ID_1, TEST_CREDENTIAL_ISSUER);
    }

    @Test
    void shouldUpdateExistingWhenUserHasUpdateRequest() {
        CriResponseItem criResponseItem =
                createCriResponseStoreItem(
                        USER_ID_1,
                        TEST_CREDENTIAL_ISSUER,
                        VC_PASSPORT_NON_DCMAW_SUCCESSFUL,
                        Instant.now());
        when(mockDataStore.update(criResponseItem)).thenReturn(criResponseItem);

        criResponseService.updateCriResponseItem(criResponseItem);
        verify(mockDataStore, times(1)).update(criResponseItem);
    }

    private CriResponseItem createCriResponseStoreItem(
            String userId, String credentialIssuer, String issuerResponse, Instant dateCreated) {
        CriResponseItem criResponseItem = new CriResponseItem();
        criResponseItem.setUserId(userId);
        criResponseItem.setCredentialIssuer(credentialIssuer);
        criResponseItem.setIssuerResponse(issuerResponse);
        criResponseItem.setDateCreated(dateCreated);
        criResponseItem.setStatus(CriResponseService.STATUS_PENDING);
        return criResponseItem;
    }
}
