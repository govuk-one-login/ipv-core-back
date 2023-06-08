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
import java.util.UUID;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;
import static uk.gov.di.ipv.core.library.domain.CriConstants.F2F_CRI;
import static uk.gov.di.ipv.core.library.fixtures.TestFixtures.SIGNED_VC_1;

@ExtendWith(MockitoExtension.class)
public class CriResponseServiceTest {
    @Mock private ConfigService mockConfigService;

    @Mock private DataStore<CriResponseItem> mockDataStore;

    private CriResponseService criResponseService;

    private static final String USER_ID_1 = "user-id-1";
    private static final String userId = "userId";
    private static final String testCredentialIssuer = F2F_CRI;

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
                createCriResponseStoreItem(USER_ID_1, "ukPassport", SIGNED_VC_1, Instant.now());

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
                                USER_ID_1, testCredentialIssuer, SIGNED_VC_1, Instant.now()));

        when(mockDataStore.getItems(userId)).thenReturn(criResponseItem);

        var criResponseItems = criResponseService.getCriResponseItems(userId);

        assertTrue(
                criResponseItems.stream()
                        .map(CriResponseItem::getCredentialIssuer)
                        .anyMatch(item -> testCredentialIssuer.equals(item)));
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
                TEST_USER_ID, TEST_CREDENTIAL_ISSUER, TEST_ISSUER_RESPONSE, TEST_OAUTH_STATE);

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
                createCriResponseStoreItem(USER_ID_1, F2F_CRI, SIGNED_VC_1, Instant.now());

        when(mockDataStore.getItem(USER_ID_1, F2F_CRI)).thenReturn(criResponseItem);

        boolean retrievedCredentialItem = criResponseService.userHasFaceToFaceRequest(USER_ID_1);

        assertTrue(retrievedCredentialItem);
    }

    private CriResponseItem createCriResponseStoreItem(
            String userId, String credentialIssuer, String issuerResponse, Instant dateCreated) {
        CriResponseItem criResponseItem = new CriResponseItem();
        criResponseItem.setUserId(userId);
        criResponseItem.setCredentialIssuer(credentialIssuer);
        criResponseItem.setIssuerResponse(issuerResponse);
        criResponseItem.setDateCreated(dateCreated);
        return criResponseItem;
    }
}
