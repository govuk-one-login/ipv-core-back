package uk.gov.di.ipv.core.library.service;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.ArgumentCaptor;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import uk.gov.di.ipv.core.library.domain.VerifiableCredential;
import uk.gov.di.ipv.core.library.persistence.DataStore;
import uk.gov.di.ipv.core.library.persistence.item.CriResponseItem;

import java.time.Instant;
import java.util.Objects;
import java.util.UUID;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;
import static uk.gov.di.ipv.core.library.domain.Cri.F2F;
import static uk.gov.di.ipv.core.library.fixtures.VcFixtures.PASSPORT_NON_DCMAW_SUCCESSFUL_VC;

@ExtendWith(MockitoExtension.class)
public class CriResponseServiceTest {
    @Mock private DataStore<CriResponseItem> mockDataStore;

    private CriResponseService criResponseService;

    private static final String USER_ID_1 = "user-id-1";
    private static final String TEST_USER_ID = UUID.randomUUID().toString();
    private static final String TEST_CREDENTIAL_ISSUER = F2F.getId();
    private static final String TEST_ISSUER_RESPONSE =
            "{\"sub\":"
                    + TEST_USER_ID
                    + "\","
                    + "\"https://vocab.account.gov.uk/v1/credentialStatus\":\"pending\"}";

    private static final String TEST_OAUTH_STATE = UUID.randomUUID().toString();

    @BeforeEach
    void setUp() {
        criResponseService = new CriResponseService(mockDataStore);
    }

    @Test
    void shouldReturnCredentialFromDataStoreForSpecificCri() {
        String ipvSessionId = "ipvSessionId";
        String criId = "criId";
        CriResponseItem criResponseItem =
                createCriResponseStoreItem(PASSPORT_NON_DCMAW_SUCCESSFUL_VC, Instant.now());

        when(mockDataStore.getItem(ipvSessionId, criId)).thenReturn(criResponseItem);

        CriResponseItem retrievedCredentialItem =
                criResponseService.getCriResponseItem(ipvSessionId, criId);

        assertEquals(criResponseItem, retrievedCredentialItem);
    }

    @Test
    void shouldPersistCriResponse() {
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
                createCriResponseStoreItem(PASSPORT_NON_DCMAW_SUCCESSFUL_VC, Instant.now());

        when(mockDataStore.getItem(USER_ID_1, F2F.getId())).thenReturn(criResponseItem);

        CriResponseItem retrievedCredentialItem =
                criResponseService.getFaceToFaceRequest(USER_ID_1);

        assertFalse(Objects.isNull(retrievedCredentialItem));
    }

    @Test
    void shouldDeleteExistingWhenUserHasDeleteRequest() {
        CriResponseItem criResponseItem =
                createCriResponseStoreItem(PASSPORT_NON_DCMAW_SUCCESSFUL_VC, Instant.now());

        when(mockDataStore.delete(USER_ID_1, TEST_CREDENTIAL_ISSUER)).thenReturn(criResponseItem);

        criResponseService.deleteCriResponseItem(USER_ID_1, TEST_CREDENTIAL_ISSUER);

        verify(mockDataStore, times(1)).delete(USER_ID_1, TEST_CREDENTIAL_ISSUER);
    }

    @Test
    void shouldUpdateExistingWhenUserHasUpdateRequest() {
        CriResponseItem criResponseItem =
                createCriResponseStoreItem(PASSPORT_NON_DCMAW_SUCCESSFUL_VC, Instant.now());
        when(mockDataStore.update(criResponseItem)).thenReturn(criResponseItem);

        criResponseService.updateCriResponseItem(criResponseItem);
        verify(mockDataStore, times(1)).update(criResponseItem);
    }

    private CriResponseItem createCriResponseStoreItem(
            VerifiableCredential vc, Instant dateCreated) {
        CriResponseItem criResponseItem = new CriResponseItem();
        criResponseItem.setUserId(vc.getUserId());
        criResponseItem.setCredentialIssuer(vc.getCriId());
        criResponseItem.setIssuerResponse(vc.getVcString());
        criResponseItem.setDateCreated(dateCreated);
        criResponseItem.setStatus(CriResponseService.STATUS_PENDING);
        return criResponseItem;
    }
}
