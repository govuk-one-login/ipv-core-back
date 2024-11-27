package uk.gov.di.ipv.core.library.service;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;
import org.junit.jupiter.params.provider.ValueSource;
import org.mockito.ArgumentCaptor;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import uk.gov.di.ipv.core.library.domain.Cri;
import uk.gov.di.ipv.core.library.domain.VerifiableCredential;
import uk.gov.di.ipv.core.library.persistence.DataStore;
import uk.gov.di.ipv.core.library.persistence.item.CriResponseItem;

import java.time.Instant;
import java.util.List;
import java.util.Objects;
import java.util.UUID;
import java.util.stream.Stream;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;
import static uk.gov.di.ipv.core.library.config.CoreFeatureFlag.EVCS_READ_ENABLED;
import static uk.gov.di.ipv.core.library.config.CoreFeatureFlag.EVCS_WRITE_ENABLED;
import static uk.gov.di.ipv.core.library.domain.Cri.ADDRESS;
import static uk.gov.di.ipv.core.library.domain.Cri.DCMAW_ASYNC;
import static uk.gov.di.ipv.core.library.domain.Cri.F2F;
import static uk.gov.di.ipv.core.library.fixtures.VcFixtures.PASSPORT_NON_DCMAW_SUCCESSFUL_VC;
import static uk.gov.di.ipv.core.library.fixtures.VcFixtures.vcAddressTwo;
import static uk.gov.di.ipv.core.library.fixtures.VcFixtures.vcDcmawAsync;
import static uk.gov.di.ipv.core.library.fixtures.VcFixtures.vcF2fIdCard;

@ExtendWith(MockitoExtension.class)
class CriResponseServiceTest {
    @Mock private DataStore<CriResponseItem> mockDataStore;

    private CriResponseService criResponseService;

    private static final String USER_ID_1 = "user-id-1";
    private static final String TEST_USER_ID = UUID.randomUUID().toString();
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
        CriResponseItem criResponseItem =
                createCriResponseStoreItem(PASSPORT_NON_DCMAW_SUCCESSFUL_VC, Instant.now());

        when(mockDataStore.getItem(ipvSessionId, ADDRESS.getId())).thenReturn(criResponseItem);

        CriResponseItem retrievedCredentialItem =
                criResponseService.getCriResponseItem(ipvSessionId, ADDRESS);

        assertEquals(criResponseItem, retrievedCredentialItem);
    }

    @Test
    void shouldPersistCriResponse() {
        List<String> featureSet =
                List.of(EVCS_WRITE_ENABLED.getName(), EVCS_READ_ENABLED.getName());
        criResponseService.persistCriResponse(
                TEST_USER_ID,
                F2F,
                TEST_ISSUER_RESPONSE,
                TEST_OAUTH_STATE,
                CriResponseService.STATUS_PENDING,
                featureSet);

        ArgumentCaptor<CriResponseItem> persistedCriResponseItemCaptor =
                ArgumentCaptor.forClass(CriResponseItem.class);
        verify(mockDataStore, times(1)).create(persistedCriResponseItemCaptor.capture(), any());
        assertEquals(1, persistedCriResponseItemCaptor.getAllValues().size());
        final CriResponseItem persistedCriResponseItem =
                persistedCriResponseItemCaptor.getAllValues().get(0);
        assertEquals(TEST_USER_ID, persistedCriResponseItem.getUserId());
        assertEquals(F2F.getId(), persistedCriResponseItem.getCredentialIssuer());
        assertEquals(TEST_ISSUER_RESPONSE, persistedCriResponseItem.getIssuerResponse());
        assertEquals(TEST_OAUTH_STATE, persistedCriResponseItem.getOauthState());
        assertEquals(featureSet, persistedCriResponseItem.getFeatureSet());
    }

    @Test
    void shouldReturnTrueWhenUserHasFaceToFaceRequest() {
        CriResponseItem criResponseItem =
                createCriResponseStoreItem(PASSPORT_NON_DCMAW_SUCCESSFUL_VC, Instant.now());

        when(mockDataStore.getItem(USER_ID_1, F2F.getId())).thenReturn(criResponseItem);

        CriResponseItem retrievedCredentialItem =
                criResponseService.getCriResponseItem(USER_ID_1, F2F);

        assertFalse(Objects.isNull(retrievedCredentialItem));
    }

    @Test
    void shouldDeleteExistingWhenUserHasDeleteRequest() {
        CriResponseItem criResponseItem =
                createCriResponseStoreItem(PASSPORT_NON_DCMAW_SUCCESSFUL_VC, Instant.now());

        when(mockDataStore.delete(USER_ID_1, F2F.getId())).thenReturn(criResponseItem);

        criResponseService.deleteCriResponseItem(USER_ID_1, F2F);

        verify(mockDataStore, times(1)).delete(USER_ID_1, F2F.getId());
    }

    @Test
    void shouldUpdateExistingWhenUserHasUpdateRequest() {
        CriResponseItem criResponseItem =
                createCriResponseStoreItem(PASSPORT_NON_DCMAW_SUCCESSFUL_VC, Instant.now());
        when(mockDataStore.update(criResponseItem)).thenReturn(criResponseItem);

        criResponseService.updateCriResponseItem(criResponseItem);
        verify(mockDataStore, times(1)).update(criResponseItem);
    }

    @Test
    void getCriResponseItemWithStateShouldGetCorrectItem() {
        // Arrange
        var criResponseItem1 =
                createCriResponseStoreItem(PASSPORT_NON_DCMAW_SUCCESSFUL_VC, Instant.now());
        var criResponseItem2 =
                createCriResponseStoreItem(PASSPORT_NON_DCMAW_SUCCESSFUL_VC, Instant.now());
        criResponseItem2.setOauthState(TEST_OAUTH_STATE);
        when(mockDataStore.getItems(USER_ID_1))
                .thenReturn(List.of(criResponseItem1, criResponseItem2));

        // Act
        var criResponseItem =
                criResponseService.getCriResponseItemWithState(USER_ID_1, TEST_OAUTH_STATE);

        // Assert
        assertTrue(criResponseItem.isPresent());
        assertEquals(criResponseItem2, criResponseItem.get());
    }

    @ParameterizedTest
    @ValueSource(booleans = {true, false})
    void getAsyncResponseStatusShouldGetDcmawStatus(boolean hasVc) {
        // Arrange
        var criResponseItem1 = createCriResponseStoreItem(vcDcmawAsync(), Instant.now());
        var criResponseItem2 = createCriResponseStoreItem(vcAddressTwo(), Instant.now());
        criResponseItem2.setOauthState(TEST_OAUTH_STATE);
        when(mockDataStore.getItems(USER_ID_1))
                .thenReturn(List.of(criResponseItem1, criResponseItem2));

        // Act
        var asyncCriStatus =
                criResponseService.getAsyncResponseStatus(
                        USER_ID_1, (Cri cri) -> hasVc, (Cri cri) -> 123, false);

        // Assert
        assertEquals(DCMAW_ASYNC, asyncCriStatus.cri());
        assertEquals(criResponseItem1.getStatus(), asyncCriStatus.incompleteStatus());
        assertEquals(!hasVc, asyncCriStatus.isAwaitingVc());
        assertEquals(hasVc, asyncCriStatus.isComplete());
    }

    @ParameterizedTest
    @MethodSource("f2fStatusExpectations")
    void getAsyncResponseStatusShouldGetF2FStatus(
            boolean hasVc,
            boolean isPendingEvcsIdentity,
            boolean expectedIsAwaitingVc,
            boolean expectedIsComplete) {
        // Arrange
        var criResponseItem1 = createCriResponseStoreItem(vcF2fIdCard(), Instant.now());
        var criResponseItem2 = createCriResponseStoreItem(vcAddressTwo(), Instant.now());
        criResponseItem2.setOauthState(TEST_OAUTH_STATE);
        when(mockDataStore.getItems(USER_ID_1))
                .thenReturn(List.of(criResponseItem1, criResponseItem2));

        // Act
        var asyncCriStatus =
                criResponseService.getAsyncResponseStatus(
                        USER_ID_1, (Cri cri) -> hasVc, (Cri cri) -> 123, isPendingEvcsIdentity);

        // Assert
        assertEquals(F2F, asyncCriStatus.cri());
        assertEquals(expectedIsAwaitingVc, asyncCriStatus.isAwaitingVc());
        assertEquals(expectedIsComplete, asyncCriStatus.isComplete());
    }

    static Stream<Arguments> f2fStatusExpectations() {
        return Stream.of(
                Arguments.of(false, false, true, false),
                Arguments.of(true, false, false, false),
                Arguments.of(false, true, true, false),
                Arguments.of(true, true, false, true));
    }

    @Test
    void getAsyncResponseStatusShouldReturnEmptyStatusIfNoCriResponseFound() {
        // Arrange
        when(mockDataStore.getItems(USER_ID_1)).thenReturn(List.of());

        // Act
        var asyncCriStatus =
                criResponseService.getAsyncResponseStatus(
                        USER_ID_1, (Cri cri) -> true, (Cri cri) -> 123, false);

        // Assert
        assertNull(asyncCriStatus.cri());
        assertNull(asyncCriStatus.iat());
        assertNull(asyncCriStatus.incompleteStatus());
        assertFalse(asyncCriStatus.isAwaitingVc());
        assertFalse(asyncCriStatus.isComplete());
    }

    private CriResponseItem createCriResponseStoreItem(
            VerifiableCredential vc, Instant dateCreated) {
        CriResponseItem criResponseItem = new CriResponseItem();
        criResponseItem.setUserId(vc.getUserId());
        criResponseItem.setCredentialIssuer(vc.getCri().getId());
        criResponseItem.setIssuerResponse(vc.getVcString());
        criResponseItem.setDateCreated(dateCreated);
        criResponseItem.setStatus(CriResponseService.STATUS_PENDING);
        return criResponseItem;
    }
}
